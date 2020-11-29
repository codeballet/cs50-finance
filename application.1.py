import os
import re

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

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

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session.get("user_id")
    portfolio = []

    # Read stock shares for user
    portfolio_response = db.execute("SELECT stocks_symbol, shares FROM users_stocks \
                                     WHERE users_id=:id ORDER BY stocks_symbol",
                                     id = user_id)

    # Read cash left for user
    cash_response = db.execute("SELECT cash FROM users WHERE id=:id", id = user_id)
    cash = cash_response[0]["cash"]
    total_value = cash


    for row in portfolio_response:
        symbol = row["stocks_symbol"]
        stock_info = lookup(symbol)
        name = stock_info["name"]
        shares = row["shares"]
        price = stock_info["price"]
        price_usd = usd(price)
        total = usd(shares * price)

        total_value += shares * price

        portfolio.append({
            'symbol': symbol,
            'name': name,
            'shares': shares,
            'price': price_usd,
            'total': total
        })

    return render_template("index.html",
                           portfolio = portfolio,
                           cash = usd(cash),
                           total_value = usd(total_value))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        # Define action
        buy = "buy"

        # Get the stock info
        symbol = request.form.get("symbol")
        stock_info = lookup(symbol)

        # Check if symbol is valid
        if stock_info == None:
            return apology("cannot find that stock symbol", 403)

        # Check user input of shares
        shares_str = request.form.get("shares")
        digits = re.search("^\d+$", shares_str)

        if not digits:
            return apology("you must enter number of shares", 403)

        shares = int(shares_str)

        # Calculate if the user can afford it
        price = stock_info["price"]
        total_price = shares * price
        user_id = session.get("user_id")
        cash_response = db.execute("SELECT cash FROM users WHERE id=:id", id=user_id)
        cash = cash_response[0]["cash"]

        # If not enough cash, inform user
        if cash < total_price:
            return render_template("buy.html", has_cash=False)

        # Make purchase and redirect to /index

        # Find out how many of the purchased stock the user has
        shares_response = db.execute("SELECT shares FROM users_stocks \
                                   WHERE users_id=:user_id AND stocks_symbol=:symbol",
                                   user_id=user_id, symbol=symbol)

        if len(shares_response) !=1:
            # User does not yet have shares in that stock

            # Check if the stock exists in stocks table
            stocks_response = db.execute("SELECT symbol FROM stocks WHERE symbol=:symbol",
                                          symbol=symbol)

            if len(stocks_response) != 1:
                # Insert the stock in the stocks table
                db.execute("INSERT INTO stocks (symbol) VALUES (:symbol)", symbol=symbol)

            # Insert shares in users_stocks table
            db.execute("INSERT INTO users_stocks (users_id, stocks_symbol, shares) \
                                   VALUES (:user_id, :symbol, :shares)",
                                   user_id=user_id, symbol=symbol, shares=shares)

        else:
            # User already has existing stock shares

            # Calculate the new total amount of shares
            existing_shares = shares_response[0]["shares"]
            new_shares = existing_shares + shares

            # Update shares in users_stocks table
            db.execute("UPDATE users_stocks SET shares=:shares \
                                WHERE users_id=:user_id AND stocks_symbol=:symbol",
                                shares=new_shares, user_id=user_id, symbol=symbol)

        # Insert order into orders table
        orders_pk = db.execute("INSERT INTO orders (datetime, action, amount, price, users_id, stocks_symbol) \
                    VALUES (datetime('now'), :action, :shares, :price, :user_id, :symbol)",
                    action=buy, shares=shares, price=price, user_id=user_id, symbol=symbol)

        # Deduct the price from the users cash, update users table
        new_cash = cash - total_price
        db.execute("UPDATE users SET cash=:cash WHERE id=:id",
                    cash=new_cash, id=user_id)

        flash(f"{shares} new {symbol} share{'s' if shares > 1 else ''} were added to your portfolio.")
        return redirect("/")

    else:
        return render_template("buy.html", has_cash=True)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session.get("user_id")
    orders = []

    # Read all orders for user
    orders_response = db.execute("SELECT * FROM orders \
                                  WHERE users_id=:id \
                                  ORDER BY datetime DESC",
                                  id = user_id)

    # Append every order as an object to the orders list
    for order in orders_response:
        date = order["datetime"].split()[0]
        symbol = order["stocks_symbol"]
        action = 'bought' if order["action"] == 'buy' else 'sold'
        price = order["price"]
        shares = order["amount"]

        orders.append({
            'date': date,
            'symbol': symbol,
            'action': action,
            'price': price,
            'shares': shares
        })

    return render_template("history.html", orders = orders)


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
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        stock_info = lookup(request.form.get("symbol"))

        if stock_info == None:
            return apology("cannot find that stock symbol", 403)
        else:
            return render_template("quote.html",
                                  no_stock_info = False,
                                  name = stock_info["name"],
                                  price = usd(stock_info["price"]),
                                  symbol = stock_info["symbol"])

    else:
        return render_template("quote.html", no_stock_info=True)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Check if username provided
        if not request.form.get("username"):
            return apology("must register username", 403)

        # Check if username already exists in database
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                        username = request.form.get("username"))

        if len(rows) == 1:
            return apology("username already taken", 403)

        # Check if password provided and is correctly typed
        if not request.form.get("password"):
            return apology("must register password", 403)

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 403)

        # Hash password
        pass_hash = generate_password_hash(request.form.get("password"),
                                          method='pbkdf2:sha512',
                                          salt_length=128)

        # Store user in database
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                  username=request.form.get("username"), hash=pass_hash)

        # Redirect user to index page
        flash("You registered successfully, now please log in.")
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        # Define action
        sell = "sell"

        # Read all the users stock symbols
        symbols = db.execute("SELECT stocks_symbol FROM users_stocks \
                              WHERE users_id=:id",
                              id = session.get("user_id"))

        # Check user input of symbol
        check_symbol = 0
        for symbol in symbols:
            if symbol["stocks_symbol"] == request.form.get("symbol"):
                check_symbol = 1

        if check_symbol == 0:
            return apology("you must enter a symbol", 403)

        symbol = request.form.get("symbol")

        # Check user input of shares
        shares_str = request.form.get("shares")
        digits = re.search("^\d+$", shares_str)

        if not digits:
            return apology("you must enter number of shares", 403)

        shares = int(shares_str)

        # Check how many shares the user has
        shares_owned_response = db.execute("SELECT shares FROM users_stocks \
                                            WHERE users_id=:id AND stocks_symbol=:symbol",
                                            id = session.get("user_id"), symbol = symbol)

        shares_owned = shares_owned_response[0]["shares"]

        # Get latest symbol info
        stock_info = lookup(request.form.get("symbol"))

        if stock_info == None:
            return apology("cannot find stock symbol", 403)

        # Adjust database for sell
        if shares_owned > shares:
            # Update users cash
            price = stock_info["price"]
            cash_adjust = shares * price
            cash_response = db.execute("SELECT cash FROM users WHERE id=:id", id = session.get("user_id"))
            cash_owned = cash_response[0]["cash"]
            db.execute("UPDATE users SET cash=:cash WHERE id=:id",
                        cash = cash_owned + cash_adjust, id = session.get("user_id"))

            # Update users_stocks shares
            shares_response = db.execute("SELECT shares FROM users_stocks \
                                          WHERE users_id=:id AND stocks_symbol=:symbol",
                                          id = session.get("user_id"), symbol = symbol)

            shares_owned = shares_response[0]["shares"]
            shares_updated = shares_owned - shares

            db.execute("UPDATE users_stocks SET shares=:shares WHERE users_id=:id AND stocks_symbol=:symbol",
                        shares = shares_updated,id = session.get("user_id"), symbol = symbol)

            # Insert new order
            db.execute("INSERT INTO orders (datetime, action, amount, price, users_id, stocks_symbol) \
                        VALUES (datetime('now'), :action, :shares, :price, :user_id, :symbol)",
                        action=sell, shares=shares, price=price, user_id=session.get("user_id"), symbol=symbol)

        else:
            # User sells all their shares or more
            shares = shares_owned

            # Update users cash
            cash_adjust = shares * stock_info["price"]
            cash_response = db.execute("SELECT cash FROM users WHERE id=:id", id = session.get("user_id"))
            cash_owned = cash_response[0]["cash"]
            db.execute("UPDATE users SET cash=:cash WHERE id=:id",
                        cash = cash_owned + cash_adjust, id = session.get("user_id"))

            # Delete users_stocks row
            db.execute("DELETE FROM users_stocks WHERE users_id=:id AND stocks_symbol=:symbol",
                        id = session.get("user_id"), symbol = symbol)

            # Insert new order
            db.execute("INSERT INTO orders (datetime, action, amount, price, users_id, stocks_symbol) \
                        VALUES (datetime('now'), :action, :shares, :price, :user_id, :symbol)",
                        action=sell, shares=shares, price=price, user_id=session.get("user_id"), symbol=symbol)

        flash(f"You sold {shares} share{'s' if shares > 1 else ''} of {symbol}.")
        return redirect("/")

    else:
        # Read all the users stock symbols
        symbols = db.execute("SELECT stocks_symbol FROM users_stocks \
                              WHERE users_id=:id",
                              id = session.get("user_id"))

        # Load the template with the symbols
        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
