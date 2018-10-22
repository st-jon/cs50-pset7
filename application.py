import os

from cs50 import SQL, eprint
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, validate

# Configure application
app = Flask(__name__)
### ###

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    symbols_own = db.execute("SELECT symbol, shares FROM transactions WHERE id = :session_id", session_id=session["user_id"])

    total_cash = 0
    grand_total = 0

    for symbol_own in symbols_own:
        symbol = symbol_own["symbol"]
        shares = symbol_own["shares"]
        stock = lookup(symbol)
        total = shares * stock["price"]
        total_cash += total
        db.execute("UPDATE transactions SET price = :price, total = :total WHERE symbol = :symbol AND user_id = :user_id",
                    price=stock["price"],
                    total=total,
                    symbol=symbol,
                    user_id=session["user_id"]
                    )

    sold = db.execute("SELECT cash FROM users WHERE id = :session_id", session_id=session["user_id"])

    portfolio = db.execute("SELECT * FROM transactions WHERE user_id = :session_id", session_id=session["user_id"])

    for i in range(len(portfolio)):
        grand_total += portfolio[i]['total']
        portfolio[i]['price'] = usd(portfolio[i]['price'])
        portfolio[i]['total'] = usd(portfolio[i]['total'])

    grand_total += sold[0]["cash"]

    return render_template("index.html", cash=usd(sold[0]["cash"]), stocks=portfolio, total=usd(total_cash), grand_total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        operation = "Buy"
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("shares must be a posative integer", 400)

        stock = lookup(request.form.get("symbol"))

        if not stock:
            return apology("must enter stock symbol", 400)

        if not shares:
            return apology("must enter number of shares", 400)

        if shares <= 0 or not isinstance(shares, int):
            return apology("must enter a round and positive number for shares", 400)

        name = stock['name']
        symbol = stock['symbol']
        price = stock['price']
        total = shares * price

        sold = db.execute("SELECT cash FROM users WHERE id = :session_id", session_id=session["user_id"])
        portfolio = db.execute("SELECT * FROM transactions WHERE user_id = :session_id", session_id=session["user_id"])
        cash = sold[0]["cash"] - (shares * price)

        for i in range(len(portfolio)):
            if portfolio[i]["symbol"] == symbol.upper():
                price = stock['price']
                new_shares = shares + portfolio[i]['shares']
                total = new_shares * price

                if cash > 0:
                    db.execute("UPDATE users SET cash = :cash WHERE id = :session_id", cash=cash, session_id=session["user_id"])

                    db.execute("UPDATE transactions SET shares = :shares, price = :price, total = :total WHERE symbol = :symbol AND user_id = :session_id",
                                shares=new_shares, price=price, total=total, symbol=symbol, session_id=session["user_id"])

                    db.execute('INSERT INTO operations (operation, symbol, shares, price, user_id) VALUES (:operation, :symbol, :shares, :price, :user_id)',
                                operation=operation, symbol=symbol, shares=shares, price=price, user_id=session["user_id"])

                    flash("Bought")
                    return redirect(url_for("index"))
                else:
                    return apology("You don't have enough cash for this transaction", 403)

        if cash > 0:
            db.execute("UPDATE users SET cash = :cash WHERE id = :session_id", cash=cash, session_id=session["user_id"])

            db.execute("INSERT INTO transactions (symbol, name, shares, price, total, user_id) VALUES (:symbol, :name, :shares, :price, :total, :user_id)",
                        symbol=symbol,
                        name=name,
                        shares=shares,
                        price=price,
                        total=total,
                        user_id=session["user_id"]
                        )

            db.execute('INSERT INTO operations (operation, symbol, shares, price, user_id) VALUES (:operation, :symbol, :shares, :price, :user_id)',
                        operation=operation, symbol=symbol, shares=shares, price=price, user_id=session["user_id"])

            flash("Bought")
            return redirect("/")
        else:
            return apology("You don't have enough cash for this transaction", 403)
    else:
        return render_template("buy.html")


@app.route("/cash", methods=["GET", "POST"])
@login_required
def cash():
    """Add cash to porfolio"""
    if request.method == "POST":

        if not request.form.get("add-cash"):
            return apology("must provide an amount", 403)

        amount = float(request.form.get("add-cash"))

        cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])

        new_cash = amount + cash[0]["cash"]

        db.execute("UPDATE users SET cash = :cash WHERE id = :user_id", cash=new_cash, user_id=session["user_id"])

        flash("cash updated")
        return redirect("/")

    else:
        return render_template("cash.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    operations = db.execute("SELECT * FROM operations WHERE user_id = :session_id", session_id=session["user_id"])

    for i in range(len(operations)):
        operations[i]['price'] = usd(operations[i]['price'])

    return render_template("history.html", operations=operations)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        if not quote:
            return apology("nothing found for this quote", 400)

        else:
            return render_template("quoted.html", name=quote["name"], price=usd(quote["price"]), symbol=quote["symbol"])

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("missing username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("missing password", 400)

        # ensure password is correctly confirm
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password do not match confirmation", 400)

        username = request.form.get('username')
        password = request.form.get('password')

        validate_pass = validate(password)

        if validate_pass == 1:
            flash("Make sure your password is at least 8 letters")
            return render_template("register.html")
        elif validate_pass == 2:
            flash("Make sure your password has a number in it")
            return render_template("register.html")
        elif validate_pass == 3:
            flash("Make sure your password has a capital letter in it")
            return render_template("register.html")
        else:
            pass_hash = generate_password_hash(password)

            result = db.execute("INSERT INTO users (username, hash) VALUES (:username, :pass_hash)",
                                username=username, pass_hash=pass_hash
                                )

            if not result:
                return apology("Username already taken", 400)

            # auto log in user
            session["user_id"] = result

            # Redirect user to home page
            return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        operation = "Sell"
        shares = int(request.form.get("shares"))
        symbol = request.form.get("symbol")
        for_sale = lookup(symbol)
        price = for_sale["price"]

        if not symbol:
            return apology("must choose a stock")

        if not shares:
            return apology("must enter number of shares")

        stock_sell = db.execute('SELECT * FROM transactions WHERE symbol = :symbol AND user_id = :user_id',
                                symbol=symbol, user_id=session["user_id"]
                                )

        new_shares = stock_sell[0]["shares"] - shares
        total = new_shares * price
        sell_id = stock_sell[0]["id"]

        sold = db.execute("SELECT cash FROM users WHERE id = :session_id", session_id=session["user_id"])
        cash = sold[0]['cash'] + (price * shares)

        if stock_sell[0]["shares"] > shares:

            db.execute('UPDATE transactions SET shares = :new_shares, total = :total, price = :price WHERE symbol = :symbol AND user_id = :user_id AND id = :sell_id',
                        new_shares=new_shares,
                        total=total,
                        price=price,
                        symbol=symbol,
                        user_id=session["user_id"],
                        sell_id=sell_id
                        )

        elif stock_sell[0]["shares"] == shares:

            db.execute("DELETE FROM transactions WHERE symbol = :symbol AND user_id = :user_id", symbol=symbol, user_id=session["user_id"])

        else:
            return apology("you don't own so many stocks", 400)

        db.execute("UPDATE users SET cash = :cash WHERE id = :session_id", cash=cash, session_id=session["user_id"])

        db.execute('INSERT INTO operations (operation, symbol, shares, price, user_id) VALUES (:operation, :symbol, :shares, :price, :user_id)',
                    operation=operation, symbol=symbol, shares=shares, price=price, user_id=session["user_id"])

        flash("Sold")
        return redirect('/')

    else:
        stocks = db.execute('SELECT symbol FROM transactions WHERE user_id = :user_id', user_id=session["user_id"])
        return render_template("sell.html", stocks=stocks)


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
