import os
import re

# from cs50 import SQL
from datetime import datetime
from decimal import Decimal, getcontext

from sqlalchemy import \
    create_engine, \
    MetaData, \
    Table, \
    Column, \
    Integer, \
    String, \
    Numeric, \
    ForeignKey, \
    select, \
    insert, \
    update, \
    delete, \
    and_

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
# db = SQL("sqlite:///finance.db")

# Configure SQLAlchemy to use SQLite database
engine = create_engine('sqlite:///finance.db', echo=True)

# Define tables for SQLAlchemy
metadata = MetaData()

users = Table('users', metadata,
    Column('id', Integer, primary_key=True),
    Column('username', String, nullable=False),
    Column('hash', String, nullable=False),
    Column('cash', String, nullable=False, default='10000.00')
)

stocks = Table('stocks', metadata,
    Column('symbol', String(5), primary_key=True, unique=True)
)

orders = Table('orders', metadata,
    Column('id', Integer, primary_key=True),
    Column('datetime', String, nullable=False),
    Column('action', String(4), nullable=False),
    Column('amount', Integer, nullable=False),
    Column('price', String, nullable=False),
    Column('users_id', ForeignKey('users.id')),
    Column('stocks_symbol', ForeignKey('stocks.symbol'))
)

users_stocks = Table('users_stocks', metadata,
    Column('users_id', ForeignKey('users.id'), primary_key=True),
    Column('stocks_symbol', ForeignKey('stocks.symbol'), primary_key=True),
    Column('shares', Integer, nullable=False)
)

# Create tables for SQLAlchemy
metadata.create_all(engine)

# Connect to SQLAlchemy engine object
conn = engine.connect()

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# Set decimal precision to two places
TWOPLACES = Decimal(10) ** -2

def mul(x, y, fp = TWOPLACES):
    return (x * y).quantize(fp)

def add(x, y, fp = TWOPLACES):
    return (x + y).quantize(fp)

def sub(x, y, fp = TWOPLACES):
    return (x - y).quantize(fp)

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session.get("user_id")
    portfolio = []

    # Read stock shares for user
    #
    # Using cs50
    # portfolio_response = db.execute("SELECT stocks_symbol, shares FROM users_stocks \
    #                                  WHERE users_id=:id ORDER BY stocks_symbol",
    #                                  id = user_id)
    # Using SQLAlchemy
    s = select([users_stocks.c.stocks_symbol, users_stocks.c.shares]).\
        where(users_stocks.c.users_id == user_id).\
        order_by(users_stocks.c.stocks_symbol)

    portfolio_response = conn.execute(s)

    # Read cash left for user
    #
    # Using cs50
    # cash_response = db.execute("SELECT cash FROM users WHERE id=:id", id = user_id)
    # cash = cash_response[0]["cash"]
    # total_value = cash
    #
    #Using SQLAlchemy
    s = select([users.c.cash]).where(users.c.id == user_id)
    cash_response = conn.execute(s).fetchone()
    cash = cash_response["cash"]
    total_value = Decimal(cash)


    for row in portfolio_response:
        symbol = row["stocks_symbol"]
        stock_info = lookup(symbol)
        name = stock_info["name"]
        shares = row["shares"]
        price = Decimal(stock_info["price"])
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
        price = mul(Decimal(stock_info["price"]), 1)
        total_price = mul(shares, price)
        user_id = session.get("user_id")
        # Read cash for user from db
        #cash_response = db.execute("SELECT cash FROM users WHERE id=:id", id=user_id)
        s = select([users.c.cash]).where(users.c.id == user_id)
        cash_response = conn.execute(s).fetchone()
        cash = Decimal(cash_response["cash"])

        # If not enough cash, inform user
        if cash < total_price:
            return render_template("buy.html", has_cash=False)

        # Make purchase and redirect to /index

        # Read the user's amount of shares for the symbol from db
        # shares_response = db.execute("SELECT shares FROM users_stocks \
        #                           WHERE users_id=:user_id AND stocks_symbol=:symbol",
        #                           user_id=user_id, symbol=symbol)
        s = select([users_stocks.c.shares]).\
            where(
                and_(
                    users_stocks.c.users_id == user_id,
                    users_stocks.c.stocks_symbol == symbol
                )
            )

        shares_response = conn.execute(s).fetchall()

        if len(shares_response) !=1:
            # User does not yet have shares in that stock

            # Check if the stock exists in stocks table
            # stocks_response = db.execute("SELECT symbol FROM stocks WHERE symbol=:symbol",
            #                               symbol=symbol)
            s = select([stocks.c.symbol]).where(stocks.c.symbol == symbol)
            stocks_response = conn.execute(s).fetchall()

            if len(stocks_response) != 1:
                # Insert the stock in the stocks table
                # db.execute("INSERT INTO stocks (symbol) VALUES (:symbol)", symbol=symbol)
                ins = insert(stocks).values(symbol=symbol)
                conn.execute(ins)

            # Insert shares in users_stocks table
            # db.execute("INSERT INTO users_stocks (users_id, stocks_symbol, shares) \
            #                       VALUES (:user_id, :symbol, :shares)",
            #                       user_id=user_id, symbol=symbol, shares=shares)
            ins = insert(users_stocks).\
                values(
                    users_id=user_id,
                    stocks_symbol=symbol,
                    shares=shares
                )
            conn.execute(ins)

        else:
            # User already has existing stock shares

            # Calculate the new total amount of shares
            existing_shares = shares_response[0]["shares"]
            new_shares = existing_shares + shares

            # Update shares in users_stocks table
            # db.execute("UPDATE users_stocks SET shares=:shares \
            #                     WHERE users_id=:user_id AND stocks_symbol=:symbol",
            #                     shares=new_shares, user_id=user_id, symbol=symbol)
            stmt = update(users_stocks).\
                where(
                    and_(
                        users_stocks.c.users_id == user_id,
                        users_stocks.c.stocks_symbol == symbol
                    )
                ).\
                values(
                    shares = new_shares
                )
            conn.execute(stmt)

        # Insert order into orders table
        # orders_pk = db.execute("INSERT INTO orders (datetime, action, amount, price, users_id, stocks_symbol) \
        #             VALUES (datetime('now'), :action, :shares, :price, :user_id, :symbol)",
        #             action=buy, shares=shares, price=price, user_id=user_id, symbol=symbol)
        ins = insert(orders).\
            values(
                datetime = datetime.now(),
                action = buy,
                amount = shares,
                price = str(price),
                users_id = user_id,
                stocks_symbol = symbol
            )

        conn.execute(ins)

        # Deduct the price from the users cash, update users table
        new_cash = sub(cash, total_price)
        # db.execute("UPDATE users SET cash=:cash WHERE id=:id",
        #             cash=new_cash, id=user_id)
        stmt = update(users).\
            where(users.c.id == user_id).\
            values(
                cash = str(new_cash)
            )

        conn.execute(stmt)

        flash(f"{shares} new {symbol} share{'s' if shares > 1 else ''} were added to your portfolio.")
        return redirect("/")

    else:
        return render_template("buy.html", has_cash=True)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session.get("user_id")
    orders_list = []

    # Read all orders for a user
    # orders_response = db.execute("SELECT * FROM orders \
    #                               WHERE users_id=:id \
    #                               ORDER BY datetime DESC",
    #                               id = user_id)
    s = select([orders.c.datetime, orders.c.stocks_symbol, orders.c.action, orders.c.price, orders.c.amount]).\
        where(orders.c.users_id == user_id).\
        order_by(orders.c.datetime.desc())

    orders_response = conn.execute(s).fetchall()

    # Append every order as an object to the orders list
    for order in orders_response:
        date = order["datetime"].split()[0]
        symbol = order["stocks_symbol"]
        action = 'bought' if order["action"] == 'buy' else 'sold'
        price = order["price"]
        shares = order["amount"]

        orders_list.append({
            'date': date,
            'symbol': symbol,
            'action': action,
            'price': usd(price),
            'shares': shares
        })

    return render_template("history.html", orders = orders_list)


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
        # rows = db.execute("SELECT * FROM users WHERE username = :username",
        #                   username=request.form.get("username"))
        s = select([users]).where(users.c.username == request.form.get("username"))

        rows = conn.execute(s).fetchall()

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
        # Ensure username is provided
        if not request.form.get("username"):
            return apology("must register username", 403)

        username = request.form.get("username")

        # Check if username already exists in database
        #
        # using cs50
        # rows = db.execute("SELECT * FROM users WHERE username = :username",
        #                 username = request.form.get("username"))
        #
        # Using SQLAlchemy
        s = select([users]).where(users.c.username == username)
        rows = conn.execute(s).fetchall()

        if len(rows) == 1:
            return apology("username already taken", 403)

        # Verify existence and spelling of password
        if not request.form.get("password"):
            return apology("must register password", 403)

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Check the spelling of your password", 403)

        password = request.form.get("password")

        # Hash password
        pass_hash = generate_password_hash(password,
                                           method='pbkdf2:sha512',
                                           salt_length=128)

        # Store user in db table users
        #
        # Using cs50
        # db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
        #           username=request.form.get("username"), hash=pass_hash)
        #
        # Using SQLAlchemy
        ins = users.insert(None).values(username=username, hash=pass_hash)
        conn.execute(ins)

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
        # symbols = db.execute("SELECT stocks_symbol FROM users_stocks \
        #                       WHERE users_id=:id",
        #                       id = session.get("user_id"))
        s = select([users_stocks.c.stocks_symbol]).\
            where(users_stocks.c.users_id == session.get("user_id"))

        symbols = conn.execute(s).fetchall()

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
        # shares_owned_response = db.execute("SELECT shares FROM users_stocks \
        #                                     WHERE users_id=:id AND stocks_symbol=:symbol",
        #                                     id = session.get("user_id"), symbol = symbol)
        s = select([users_stocks.c.shares]).\
            where(
                and_(
                    users_stocks.c.users_id == session.get("user_id"),
                    users_stocks.c.stocks_symbol == symbol
                )
            )

        shares_owned_response = conn.execute(s).fetchone()

        shares_owned = shares_owned_response["shares"]

        # Get latest symbol info
        stock_info = lookup(symbol)

        if stock_info == None:
            return apology("cannot find stock symbol", 403)

        # Get current price for the symbol
        price = Decimal(stock_info["price"])

        # Adjust database for sell action

        # Read users current cash
        # cash_response = db.execute("SELECT cash FROM users WHERE id=:id", id = session.get("user_id"))
        s = select([users.c.cash]).where(users.c.id == session.get("user_id"))

        cash_response = conn.execute(s).fetchone()

        cash_owned = Decimal(cash_response["cash"])

        # If the user entered less shares than they own
        if shares_owned > shares:
            # Calculate amount to adjust for users cash
            cash_adjust = mul(shares, price)

            # Update users cash
            # db.execute("UPDATE users SET cash=:cash WHERE id=:id",
            #             cash = cash_owned + cash_adjust, id = session.get("user_id"))
            stmt = update(users).where(users.c.id == session.get("user_id")).\
                values(cash = str(add(cash_owned, cash_adjust)))

            conn.execute(stmt)


            # Read users_stocks shares
            # shares_response = db.execute("SELECT shares FROM users_stocks \
            #                               WHERE users_id=:id AND stocks_symbol=:symbol",
            #                               id = session.get("user_id"), symbol = symbol)
            s = select([users_stocks.c.shares]).\
                where(
                    and_(
                        users_stocks.c.users_id == session.get("user_id"),
                        users_stocks.c.stocks_symbol == symbol
                    )
                )

            shares_response = conn.execute(s).fetchone()

            shares_owned = shares_response["shares"]

            # Calculate the new number of shares
            shares_updated = shares_owned - shares
            print(f'shares_owned: {shares_owned}')
            print(f'shares: {shares}')
            print(f'shares_updated: {shares_updated}')

            # Update users_stocks table with new number of shares
            # db.execute("UPDATE users_stocks SET shares=:shares WHERE users_id=:id AND stocks_symbol=:symbol",
            #             shares = shares_updated, id = session.get("user_id"), symbol = symbol)
            stmt = update(users_stocks).\
                where(
                    and_(
                        users_stocks.c.users_id == session.get("user_id"),
                        users_stocks.c.stocks_symbol == symbol
                    )
                ).\
                values(shares = shares_updated)

            conn.execute(stmt)

        # Else, user entered more than or equal to number of shares than they own
        else:
            # Restrict user to sell only the number of shares they own
            shares = shares_owned

            # Update users cash
            # Calculate change in cash to adjust
            cash_adjust = mul(shares, price)

            # Update users cash
            # db.execute("UPDATE users SET cash=:cash WHERE id=:id",
            #             cash = cash_owned + cash_adjust, id = session.get("user_id"))
            stmt = update(users).where(users.c.id == session.get("user_id")).\
                values(cash = str(add(cash_owned, cash_adjust)))

            conn.execute(stmt)

            # Delete users_stocks table row, as user has no more stocks of that kind
            # db.execute("DELETE FROM users_stocks WHERE users_id=:id AND stocks_symbol=:symbol",
            #             id = session.get("user_id"), symbol = symbol)
            stmt = delete(users_stocks).\
                where(
                    and_(
                        users_stocks.c.users_id == session.get("user_id"),
                        users_stocks.c.stocks_symbol == symbol
                    )
                )

            conn.execute(stmt)

        # Insert new order into orders table
        # db.execute("INSERT INTO orders (datetime, action, amount, price, users_id, stocks_symbol) \
        #             VALUES (datetime('now'), :action, :shares, :price, :user_id, :symbol)",
        #             action=sell, shares=shares, price=price, user_id=session.get("user_id"), symbol=symbol)
        ins = insert(orders).\
            values(
                datetime = datetime.now(),
                action = sell,
                amount = shares,
                price = str(mul(price, 1)),
                users_id = session.get("user_id"),
                stocks_symbol = symbol
            )

        conn.execute(ins)

        flash(f"You sold {shares} share{'s' if shares > 1 else ''} of {symbol}.")
        return redirect("/")

    else:
        # Read all the users stock symbols
        # symbols = db.execute("SELECT stocks_symbol FROM users_stocks \
        #                       WHERE users_id=:id",
        #                       id = session.get("user_id"))
        s = select([users_stocks.c.stocks_symbol]).\
            where(users_stocks.c.users_id == session.get("user_id"))

        symbols = conn.execute(s).fetchall()

        # Load the template with the symbols
        return render_template("sell.html", symbols=symbols)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Change password"""

    if request.method == "POST":
        # Ensure old password is provided
        if not request.form.get("old_password"):
            return apology("You must provide your existing password", 403)

        # Read database old password and verify
        s = select([users.c.hash]).where(users.c.id == session.get("user_id"))

        password_response = conn.execute(s).fetchone()
        print(f'password_response: {password_response}')

        # Ensure password is correct
        if not check_password_hash(password_response[0], request.form.get("old_password")):
            return apology("You entered wrong password", 403)

        # Ensure new password is provided
        if not request.form.get("new_password"):
            return apology("You must provide a new password", 403)

        # Verify spelling of new password
        if request.form.get("new_password") != request.form.get("confirm_new_password"):
            return apology("Check the spelling of your new password", 403)

        # Hash new password
        new_pass_hash = generate_password_hash(request.form.get("new_password"),
                                               method='pbkdf2:sha512',
                                               salt_length=128)

        # Update password in db table users
        stmt = update(users).\
            where(users.c.id == session.get("user_id")).\
            values(hash = new_pass_hash)

        conn.execute(stmt)

        # Redirect user to index page
        flash("You successfully changed your password")
        return redirect("/")

    else:
        return render_template("settings.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
