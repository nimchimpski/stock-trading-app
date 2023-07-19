import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
import datetime
import pytz

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")
db.execute("CREATE TABLE IF NOT EXISTS transactions (log INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, date INTEGER, id TEXT, stock TEXT, trade TEXT, price REAL, quantity INTEGER, total REAL)")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""

    if request.method == "POST":
        id = session["user_id"]
        print("///session", session)
        stock = request.form.get("stock")
        print("///stock///", stock)
        quantity = request.form.get("quantity")

        print("///quantity///", quantity, type(quantity))
        trade = request.form.get("trade")
        print("///trade///", trade)
        price = float(request.form.get("price"))
        print("///price///", price, type(price))
        cash = float(request.form.get("cash"))
        print("///cash///", cash)
        quantityowned = int(request.form.get("quantityowned"))

        print("///quantityowned///", quantityowned, type(quantityowned))

        # check form
        if not trade or not quantity:
            flash("Both trade type and quantity must be selected and entered.", "error")
            return redirect("/")

        quantity = int(quantity)
        cost = price * quantity
        print("///cost", type(cost))
        if trade == "buy":
            if cost > cash:
                return apology("You're too poor")
            cash -= cost
        elif trade == "sell":
            if not quantityowned or quantityowned < quantity:
                return apology("you dont own enough of these shares")
            cash += cost
            quantity *= -1

        # database update block
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, id)
        date = datetime.datetime.now(pytz.timezone("US/Eastern"))
        print("///date", type(date))
        trade = "buy"
        db.execute("INSERT INTO transactions (date, id, stock, trade, price, quantity, total) VALUES (?,?,?,?,?,?,?)",
                   date, id, stock, trade, price, quantity, cost)

        return redirect("/")

    id = session["user_id"]
    print("///session", session)
    sharesheld = db.execute("SELECT DISTINCT(stock), SUM(quantity) FROM transactions WHERE id = ? GROUP BY stock", id)
    print("///sharesheld", sharesheld, type(sharesheld))
    i = 0
    for share in sharesheld:
        print("///Indexquantity, [i]", share['SUM(quantity)'], i)
        if share['SUM(quantity)'] == 0:
            del sharesheld[i]
        i += 1
    j = 0
    totalsharesval = 0
    for share in sharesheld:
        price = lookup(share['stock'])
        priceprice = price['price']
        print("///priceprice", priceprice, type(priceprice))
        sharesheld[j]['price'] = priceprice
        # print("///share[price]", share['price'])
        sharesheld[j]['value'] = (share['price'] * share['SUM(quantity)'])
        totalsharesval += share['value']
        j += 1
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    print("///cash", cash)
    grandtotal = cash[0]['cash'] + totalsharesval
    print("///total", totalsharesval)
    print("///grandtotal", grandtotal)
    print("///", type(totalsharesval), type(cash[0]["cash"]), type(grandtotal))

    usernamelist = db.execute("SELECT username FROM users WHERE id = ?", id)
    username = usernamelist[0]['username']

    return render_template("index.html", username=username, sharesheld=sharesheld, totalsharesval=totalsharesval, cash=cash[0]['cash'], grandtotal=grandtotal)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        id = session["user_id"]
        # check form is filled
        stock = request.form.get("symbol")
        quantity = request.form.get("shares")
        print("///quantity", quantity, type(quantity))
        if not stock or not quantity or not quantity.isdigit():
            return apology("Fill in both forms correctly")
        quantity = int(quantity)
        if quantity < 1:
            return apology("minimum 1 share")
        print("///quantity", type(quantity))

        # check if stock exists
        print("///lookup", type(lookup(stock)))
        if lookup(stock) is None:
            return apology("no such stock")

        # check affordability
        pricedict = lookup(stock)
        if not pricedict:
            return apology("symbol not recognised")
        print("///pricedict", type(pricedict))
        pricefloat = pricedict["price"]
        print("///pricefloat", type(pricefloat))
        # buy block
        cost = pricefloat * quantity
        print("///cost", type(cost))

        cashlist = db.execute("SELECT cash FROM users WHERE id = ?", id)
        print("///cashlist", type(cashlist))
        cash = int(cashlist[0]["cash"])
        print("///cash", type(cost))
        if cost > cash:
            return apology("You're too poor")
        # database update block
        db.execute("UPDATE users SET cash = ? WHERE id = ?", (cash-cost), id)
        date = datetime.datetime.now(pytz.timezone("US/Eastern"))
        print("///date", type(date))
        trade = "buy"
        db.execute("INSERT INTO transactions (date, id, stock, trade, price, quantity, total) VALUES (?,?,?,?,?,?,?)",
                   date, id, stock, trade, pricefloat, quantity, cost)

        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    id = session["user_id"]
    historylist = db.execute("SELECT date, stock, trade, price, quantity, total FROM transactions WHERE id = ?", id)
    print("///historylist", historylist)

    for i in historylist:
        i['quantity'] = abs(i['quantity'])

    return render_template("history.html", history=historylist)
    # return apology("TODO")


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("needs symbol")
        quote = lookup(symbol)

        if not quote:
            return apology("crap symbol")
        return render_template("quoted.html", quote=quote)

    # return apology("TODO")
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        namesdict = db.execute("SELECT username FROM users")
        print("///namesdict///", namesdict)
        username = request.form.get("username")
        # create list of existing usernames to search
        nameslist = []
        for i in namesdict:
            nameslist.append(i['username'])

        if not username or username in nameslist:
            return apology("no username or username already taken", 400)

        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not password or not confirmation or confirmation != password:
            return apology("please enter password in both boxes")
        else:

            pwhash = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES (?,?)", username, pwhash)
            flash("Registration successful")
        return redirect("/login")
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        id = session["user_id"]
        # check form is filled in
        stock = request.form.get("symbol")
        quantity = request.form.get("shares")
        print("///quantity", quantity, type(quantity))
        if not stock or not quantity or not quantity.isdigit():
            return apology("fill in both forms correctly")
        quantity = float(quantity)
        if quantity < 1:
            return apology("minimum 1 share")
        print("///quantity", type(quantity))

        # check if stock exists
        print("///lookup", type(lookup(stock)))
        if lookup(stock) is None:
            return apology("no such stock")

        # check enough shares are owned
        quantityowned = db.execute("SELECT SUM(quantity) FROM transactions WHERE stock = ? and id =?", stock, id)
        print("///quantityowned", quantityowned, type(quantityowned))
        if quantityowned[0]['SUM(quantity)'] is None:
            return apology("you dont own this stock")
        if quantity > (quantityowned[0]["SUM(quantity)"]):
            return apology("you dont have enough shares to make this sale")
        # calculate value of the shares to sell
        pricedict = lookup(stock)
        print("///pricedict", type(pricedict))
        pricefloat = pricedict["price"]
        print("///pricefloat", type(pricefloat))
        value = pricefloat * quantity
        print("///value", type(value))
        # update cash in users table
        cashlist = db.execute("SELECT cash FROM users WHERE id = ?", id)
        print("///cashlist[0]['cash']", type(cashlist[0]["cash"]))
        cash = int(cashlist[0]["cash"])
        print("///cash", type(cash))
        db.execute("UPDATE users SET cash = ? WHERE id = ?", (cash+value), id)
        # record transaction in transactions table
        date = datetime.datetime.now(pytz.timezone("US/Eastern"))
        print("///date", type(date))
        trade = "sell"
        db.execute("INSERT INTO transactions (date, id, stock, trade, price, quantity, total) VALUES (?,?,?,?,?,?,?)",
                   date, id, stock, trade, pricefloat, (quantity * -1), value)

        return redirect("/")

    id = session["user_id"]
    stocks = db.execute("SELECT DISTINCT(stock) FROM transactions WHERE id = ?", id)
    return render_template("sell.html", stocks=stocks)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """account settings"""
    id = session['user_id']
    if request.method == "POST":
        # check oldpassword password is correct
        existinghashlist = db.execute("SELECT hash FROM users WHERE id = ?", id)
        print("///existinghashlist", existinghashlist)
        print("////dbhash", existinghashlist[0]["hash"])
        if not check_password_hash(existinghashlist[0]["hash"], request.form.get('oldpassword')):
            return apology("invalid  password", 403)
        # check new passwords match
        newpassword = request.form.get("newpassword")
        confirmation = request.form.get("confirmation")

        if not newpassword or not confirmation or confirmation != newpassword:
            return apology("please enter password in both boxes")
        else:
            newpwhash = generate_password_hash(newpassword)
            db.execute(" UPDATE users SET hash = ? WHERE id = ?", newpwhash, id)
        return redirect("/login")

    return render_template("account.html")