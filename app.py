import csv
import hmac
import io
import os
import re
import tempfile
from decimal import Decimal, ROUND_HALF_UP
from functools import wraps
from io import BytesIO
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator
from xml.sax.saxutils import escape

import bcrypt
import jwt
import pymysql
from dotenv import load_dotenv
from flask import Flask, Response, g, jsonify, request, send_file, send_from_directory
from pymysql.constants import FIELD_TYPE
from pymysql.converters import conversions
from pymysql.cursors import DictCursor
from werkzeug.exceptions import HTTPException
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.join(BASE_DIR, "public")
load_dotenv(os.path.join(BASE_DIR, ".env"))

SECRET = os.getenv("JWT_SECRET", "")
if not SECRET:
    raise SystemExit("JWT_SECRET is not set. Add it to .env or the Render environment.")

# Aiven requires SSL: use ca.pem next to app.py, or the certificate text in DB_CA.
CA: str | None = None
if os.getenv("DB_SSL") == "true":
    ca_file = os.path.join(BASE_DIR, "ca.pem")
    ca_text = os.getenv("DB_CA", "")
    if os.path.exists(ca_file):
        CA = ca_file
    elif ca_text:
        CA = os.path.join(tempfile.gettempdir(), "ca.pem")
        with open(CA, "w") as f:
            f.write(ca_text)

# Decimals come back as numbers and dates as text, so the JSON suits the frontend.
conv: dict[Any, Any] = dict(conversions)
conv[FIELD_TYPE.NEWDECIMAL] = float
conv[FIELD_TYPE.DECIMAL] = float
for _t in (FIELD_TYPE.DATE, FIELD_TYPE.DATETIME, FIELD_TYPE.TIMESTAMP):
    conv[_t] = str


def connect() -> Any:
    params: dict[str, Any] = {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": int(os.getenv("DB_PORT", "3306")),
        "user": os.getenv("DB_USER", "root"),
        "password": os.getenv("DB_PASSWORD", ""),
        "database": os.getenv("DB_NAME", "defaultdb"),
        "ssl_ca": CA,
        "cursorclass": DictCursor,
        "conv": conv,
        "autocommit": False,
        "connect_timeout": 15,
    }
    return pymysql.connect(**params)


@contextmanager
def tx() -> Iterator[Any]:
    """One database transaction: commits on success, rolls back on any error."""
    c = connect()
    try:
        yield c.cursor()
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def select(sql: str, args: Any = ()) -> list[dict[str, Any]]:
    with tx() as cur:
        cur.execute(sql, args)
        return list(cur.fetchall())


def execute(sql: str, args: Any = ()) -> int:
    with tx() as cur:
        cur.execute(sql, args)
        return cur.lastrowid


app = Flask(__name__, static_folder=PUBLIC, static_url_path="")


class ApiError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


@app.errorhandler(Exception)
def on_error(err: Exception) -> Any:
    if isinstance(err, HTTPException):
        return err
    if isinstance(err, ApiError):
        return jsonify(error=str(err)), err.status
    if isinstance(err, pymysql.err.IntegrityError):
        msgs = {
            1062: "That value already exists (duplicate SKU or username)",
            1451: "Cannot delete: it is used by sales or orders",
        }
        return jsonify(error=msgs.get(err.args[0], "That change breaks a data rule")), 400
    app.logger.exception("Unhandled error")
    return jsonify(error="Server error. Check the terminal for details."), 500


@app.get("/")
def home() -> Any:
    return send_from_directory(PUBLIC, "index.html")


# ---------- Helpers ----------
def body() -> dict[str, Any]:
    return request.get_json(silent=True) or {}


def num(v: Any, label: str, integer: bool = False) -> Any:
    try:
        n = float(v)
    except (TypeError, ValueError):
        n = 0.0
    if n < 0:
        raise ApiError(f"{label} cannot be negative")
    return int(n) if integer else n


def hash_pw(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def auth(*roles: str) -> Any:
    def deco(f: Any) -> Any:
        @wraps(f)
        def wrapper(*a: Any, **k: Any) -> Any:
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            try:
                g.user = jwt.decode(token, SECRET, algorithms=["HS256"])
            except Exception:
                return jsonify(error="Please log in"), 401
            if roles and g.user["role"] not in roles:
                return jsonify(error="Not allowed for your role"), 403
            return f(*a, **k)
        return wrapper
    return deco


# ---------- Login ----------
@app.post("/api/login")
def login() -> Any:
    d = body()
    rows = select("SELECT * FROM users WHERE username=%s", (d.get("username"),))
    u = rows[0] if rows else None
    if not u or not bcrypt.checkpw(str(d.get("password") or "").encode(), u["password"].encode()):
        raise ApiError("Wrong username or password", 401)
    user = {"id": u["id"], "name": u["name"], "username": u["username"], "role": u["role"]}
    exp = datetime.now(timezone.utc) + timedelta(hours=12)
    return {"token": jwt.encode({**user, "exp": exp}, SECRET, algorithm="HS256"), "user": user}

# ---------- Self sign-up (staff create their own cashier account) ----------
@app.post("/api/signup")
def signup() -> Any:
    d = body()
    code = os.getenv("STORE_CODE", "")
    if not code:
        raise ApiError("Sign-up is turned off. Ask the store owner to create your account.", 403)
    if not hmac.compare_digest(str(d.get("code") or "").encode(), code.encode()):
        raise ApiError("Wrong store code. Ask the store owner for it.", 403)
    username, password = str(d.get("username") or "").strip(), str(d.get("password") or "")
    if len(username) < 3 or len(password) < 8:
        raise ApiError("Username needs 3+ characters and password 8+ characters")
    new_id = execute("INSERT INTO users(username,name,password,role) VALUES(%s,%s,%s,'cashier')",
                     (username, str(d.get("name") or username).strip(), hash_pw(password)))
    user = {"id": new_id, "name": str(d.get("name") or username).strip(), "username": username, "role": "cashier"}
    exp = datetime.now(timezone.utc) + timedelta(hours=12)
    return {"token": jwt.encode({**user, "exp": exp}, SECRET, algorithm="HS256"), "user": user}


# ---------- Generic CRUD (products, customers, suppliers) ----------
ENTITIES = {
    "products": ["sku", "name", "price", "cost", "stock", "reorder_level", "hsn_code", "gst_rate"],
    "customers": ["name", "phone", "email", "gstin", "state", "address"],
    "suppliers": ["name", "phone", "email"],
}
INT_COLS = ("stock", "reorder_level")
NUM_COLS = ("price", "cost", "gst_rate")


def val(d: dict[str, Any], c: str) -> Any:
    v = d.get(c)
    if c in INT_COLS:
        return num(v, c.replace("_", " ").capitalize(), True)
    if c in NUM_COLS:
        n = num(v, c.replace("_", " ").capitalize())
        if c == "gst_rate" and n > 28:
            raise ApiError("GST rate cannot exceed 28%")
        return n
    return None if v in ("", None) else v


def register(t: str, cols: list[str], writers: list[str]) -> None:
    marks = ",".join(["%s"] * len(cols))
    sets = ",".join(c + "=%s" for c in cols)

    @app.get(f"/api/{t}", endpoint=f"{t}_list")
    @auth()
    def list_() -> Any:
        return select(f"SELECT * FROM {t} ORDER BY name")

    @app.post(f"/api/{t}", endpoint=f"{t}_add")
    @auth(*writers)
    def add() -> Any:
        d = body()
        return {"id": execute(f"INSERT INTO {t}({','.join(cols)}) VALUES({marks})", [val(d, c) for c in cols])}

    @app.put(f"/api/{t}/<int:id>", endpoint=f"{t}_edit")
    @auth(*writers)
    def edit(id: int) -> Any:
        d = body()
        execute(f"UPDATE {t} SET {sets} WHERE id=%s", [val(d, c) for c in cols] + [id])
        return {"ok": True}

    @app.delete(f"/api/{t}/<int:id>", endpoint=f"{t}_delete")
    @auth("admin")
    def delete(id: int) -> Any:
        execute(f"DELETE FROM {t} WHERE id=%s", (id,))
        return {"ok": True}


for _name, _cols in ENTITIES.items():
    register(_name, _cols, ["admin", "cashier"] if _name == "customers" else ["admin"])


# ---------- Staff ----------
def role_ok(r: Any) -> str:
    return r if r in ("admin", "cashier") else "cashier"


@app.get("/api/users")
@auth("admin")
def users_list() -> Any:
    return select("SELECT id,username,name,role FROM users ORDER BY name")


@app.post("/api/users")
@auth("admin")
def users_add() -> Any:
    d = body()
    if not d.get("username") or not d.get("password"):
        raise ApiError("Username and password are required")
    new_id = execute("INSERT INTO users(username,name,password,role) VALUES(%s,%s,%s,%s)",
                     (d["username"], d.get("name"), hash_pw(str(d["password"])), role_ok(d.get("role"))))
    return {"id": new_id}


@app.put("/api/users/<int:id>")
@auth("admin")
def users_edit(id: int) -> Any:
    d = body()
    execute("UPDATE users SET username=%s,name=%s,role=%s WHERE id=%s",
            (d.get("username"), d.get("name"), role_ok(d.get("role")), id))
    if d.get("password"):
        execute("UPDATE users SET password=%s WHERE id=%s", (hash_pw(str(d["password"])), id))
    return {"ok": True}


@app.delete("/api/users/<int:id>")
@auth("admin")
def users_delete(id: int) -> Any:
    if id == g.user["id"]:
        raise ApiError("You cannot delete your own account")
    execute("DELETE FROM users WHERE id=%s", (id,))
    return {"ok": True}


# ---------- Billing / POS, GST invoices, returns and refunds ----------
def money_decimal(value: Any) -> Decimal:
    try:
        result = Decimal(str(value or 0)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception:
        raise ApiError("Invalid money value")
    if result < 0:
        raise ApiError("Money values cannot be negative")
    return result


def state_code(value: Any) -> str:
    text = str(value or "").strip()
    return text[:2] if len(text) >= 2 and text[:2].isdigit() else ""


def store_profile() -> dict[str, str]:
    gstin = os.getenv("STORE_GSTIN", "").strip().upper()
    configured_code = os.getenv("STORE_STATE_CODE", "").strip()
    if configured_code.isdigit():
        configured_code = configured_code.zfill(2)
    else:
        configured_code = ""
    return {
        "name": os.getenv("STORE_NAME", "Your Store").strip(),
        "address": os.getenv("STORE_ADDRESS", "").strip(),
        "phone": os.getenv("STORE_PHONE", "").strip(),
        "email": os.getenv("STORE_EMAIL", "").strip(),
        "gstin": gstin,
        "state": os.getenv("STORE_STATE", "").strip(),
        "state_code": configured_code or state_code(gstin),
    }


def gst_is_interstate(place: str, place_gstin: str = "") -> bool:
    store = store_profile()
    destination_code = state_code(place_gstin) or state_code(place)
    origin_code = store["state_code"]
    if destination_code and origin_code:
        return destination_code != origin_code
    if place and store["state"] and not destination_code:
        return place.casefold().strip() != store["state"].casefold().strip()
    if origin_code and not destination_code:
        raise ApiError("Enter the customer's state code or customer GSTIN so the app can determine CGST/SGST vs IGST")
    if any(os.getenv(k) for k in ("STORE_GSTIN", "STORE_STATE", "STORE_STATE_CODE")):
        raise ApiError("Set the customer's place of supply (state) and configure STORE_STATE or STORE_STATE_CODE before billing GST")
    return False


@app.get("/api/config")
@auth()
def app_config() -> Any:
    store = store_profile()
    return {"store": store, "gstConfigured": bool(store["gstin"] and store["state_code"])}


@app.post("/api/sales")
@auth()
def sales_add() -> Any:
    d = body()
    items = d.get("items") or []
    discount = money_decimal(d.get("discount"))
    if not items:
        raise ApiError("Cart is empty")
    place = str(d.get("place_of_supply") or "").strip()
    customer_gstin = str(d.get("customer_gstin") or "").strip().upper()
    customer_id = d.get("customer_id") or None
    with tx() as cur:
        if customer_id:
            cur.execute("SELECT state,gstin FROM customers WHERE id=%s", (customer_id,))
            customer = cur.fetchone()
            if customer:
                place = place or str(customer.get("state") or "").strip()
                customer_gstin = customer_gstin or str(customer.get("gstin") or "").strip().upper()
        if customer_gstin and not re.fullmatch(r"[0-9A-Z]{15}", customer_gstin):
            raise ApiError("Customer GSTIN must be 15 letters/numbers")
        prepared: list[dict[str, Any]] = []
        subtotal = Decimal("0.00")
        for item in items:
            qty = num(item.get("qty"), "Quantity", True)
            cur.execute("SELECT * FROM products WHERE id=%s FOR UPDATE", (item.get("product_id"),))
            product = cur.fetchone()
            if not product or qty < 1 or product["stock"] < qty:
                raise ApiError("Not enough stock for " + (product["name"] if product else "item"))
            price = money_decimal(product["price"])
            gross = (price * qty).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            rate = money_decimal(product.get("gst_rate", 0))
            if rate > Decimal("28.00"):
                raise ApiError("GST rate cannot exceed 28%. Check the product tax rate.")
            subtotal += gross
            prepared.append({"product": product, "qty": qty, "price": price, "gross": gross, "rate": rate})
        subtotal = subtotal.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        if discount > subtotal:
            raise ApiError("Discount cannot exceed the subtotal")
        has_gst = any(x["rate"] > 0 for x in prepared)
        profile = store_profile()
        if has_gst and (not re.fullmatch(r"[0-9A-Z]{15}", profile["gstin"]) or not profile["state_code"]):
            raise ApiError("GST is selected on a product. Configure a valid 15-character STORE_GSTIN and STORE_STATE_CODE (or STORE_STATE) before billing GST.")
        if has_gst and not place:
            place = profile["state"] or profile["state_code"]
        interstate = gst_is_interstate(place, customer_gstin) if has_gst else False
        remaining_discount = discount
        taxable_total = cgst_total = sgst_total = igst_total = tax_total = Decimal("0.00")
        line_values: list[dict[str, Any]] = []
        for idx, line in enumerate(prepared):
            if idx == len(prepared) - 1:
                line_discount = remaining_discount
            elif subtotal:
                line_discount = (discount * line["gross"] / subtotal).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                line_discount = min(line_discount, remaining_discount)
            else:
                line_discount = Decimal("0.00")
            remaining_discount -= line_discount
            taxable = (line["gross"] - line_discount).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            tax = (taxable * line["rate"] / Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            cgst = Decimal("0.00")
            sgst = Decimal("0.00")
            igst = Decimal("0.00")
            if interstate:
                igst = tax
            else:
                cgst = (tax / Decimal("2")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                sgst = tax - cgst
            taxable_total += taxable
            cgst_total += cgst
            sgst_total += sgst
            igst_total += igst
            tax_total += tax
            line_values.append({**line, "discount": line_discount, "taxable": taxable,
                                "tax": tax, "cgst": cgst, "sgst": sgst, "igst": igst})
        total = (taxable_total + tax_total).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        cur.execute("""INSERT INTO sales(customer_id,user_id,total,discount,subtotal,taxable_amount,
                       cgst,sgst,igst,tax_total,place_of_supply,customer_gstin,store_gstin,gst_state,status)
                       VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'completed')""",
                    (customer_id, g.user["id"], float(total), float(discount), float(subtotal),
                     float(taxable_total), float(cgst_total), float(sgst_total), float(igst_total), float(tax_total),
                     place or None, customer_gstin or None, store_profile()["gstin"] or None,
                     store_profile()["state"] or None))
        sale_id = cur.lastrowid
        invoice_no = f"INV-{datetime.now().strftime('%Y%m%d')}-{sale_id:06d}"
        cur.execute("UPDATE sales SET invoice_no=%s WHERE id=%s", (invoice_no, sale_id))
        for line in line_values:
            product = line["product"]
            cur.execute("UPDATE products SET stock=stock-%s WHERE id=%s", (line["qty"], product["id"]))
            cur.execute("""INSERT INTO sale_items(sale_id,product_id,qty,price,hsn_code,tax_rate,
                           discount_amount,taxable_value,cgst,sgst,igst,tax_amount,returned_qty)
                           VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0)""",
                        (sale_id, product["id"], line["qty"], float(line["price"]), product.get("hsn_code"),
                         float(line["rate"]), float(line["discount"]), float(line["taxable"]),
                         float(line["cgst"]), float(line["sgst"]), float(line["igst"]), float(line["tax"])))
    return {"id": sale_id, "invoice_no": invoice_no, "subtotal": float(subtotal), "discount": float(discount),
            "taxable_amount": float(taxable_total), "cgst": float(cgst_total), "sgst": float(sgst_total),
            "igst": float(igst_total), "tax_total": float(tax_total), "total": float(total)}


@app.get("/api/sales")
@auth()
def sales_list() -> Any:
    sql = """SELECT s.id,s.invoice_no,s.total,s.discount,s.subtotal,s.taxable_amount,s.cgst,s.sgst,s.igst,
                    s.tax_total,s.status,s.created_at,c.name AS customer,u.name AS cashier
             FROM sales s LEFT JOIN customers c ON c.id=s.customer_id
             LEFT JOIN users u ON u.id=s.user_id {} ORDER BY s.id DESC LIMIT 200"""
    if g.user["role"] == "admin":
        return select(sql.format(""))
    return select(sql.format("WHERE s.user_id=%s"), (g.user["id"],))


def readable_sale(id: int) -> dict[str, Any]:
    rows = select("""SELECT s.*,c.name AS customer_name,c.phone AS customer_phone,c.email AS customer_email,
                          c.address AS customer_address,c.gstin AS customer_profile_gstin,c.state AS customer_state,
                          u.name AS cashier FROM sales s LEFT JOIN customers c ON c.id=s.customer_id
                   LEFT JOIN users u ON u.id=s.user_id WHERE s.id=%s""", (id,))
    if not rows:
        raise ApiError("Sale not found", 404)
    sale = rows[0]
    if g.user["role"] != "admin" and sale["user_id"] != g.user["id"]:
        raise ApiError("Not allowed to view this sale", 403)
    sale["items"] = select("""SELECT si.*,p.name AS product_name,p.sku FROM sale_items si
                              LEFT JOIN products p ON p.id=si.product_id WHERE si.sale_id=%s ORDER BY si.id""", (id,))
    sale["returns"] = select("SELECT id,return_no,refund_amount,reason,created_at FROM sales_returns WHERE sale_id=%s ORDER BY id DESC", (id,))
    return sale


@app.get("/api/sales/<int:id>")
@auth()
def sale_detail(id: int) -> Any:
    return readable_sale(id)


@app.get("/api/returns")
@auth("admin")
def returns_list() -> Any:
    return select("""SELECT r.*,s.invoice_no,s.id AS sale_id,u.name AS processed_by
                     FROM sales_returns r JOIN sales s ON s.id=r.sale_id
                     LEFT JOIN users u ON u.id=r.user_id ORDER BY r.id DESC LIMIT 200""")


@app.post("/api/sales/<int:id>/returns")
@auth("admin")
def sales_return(id: int) -> Any:
    d = body()
    items = d.get("items") or []
    if not items:
        raise ApiError("Select at least one item to return")
    reason = str(d.get("reason") or "Customer return").strip()[:250]
    restock = bool(d.get("restock", True))
    with tx() as cur:
        cur.execute("SELECT * FROM sales WHERE id=%s FOR UPDATE", (id,))
        sale = cur.fetchone()
        if not sale:
            raise ApiError("Sale not found", 404)
        selected: list[tuple[dict[str, Any], int]] = []
        seen: set[int] = set()
        for item in items:
            try:
                sale_item_id = int(item.get("sale_item_id"))
            except (TypeError, ValueError):
                raise ApiError("Invalid sale item")
            qty = num(item.get("qty"), "Return quantity", True)
            if sale_item_id in seen or qty < 1:
                raise ApiError("Return quantities must be positive and each line may appear once")
            seen.add(sale_item_id)
            cur.execute("SELECT * FROM sale_items WHERE id=%s AND sale_id=%s FOR UPDATE", (sale_item_id, id))
            line = cur.fetchone()
            if not line or qty > int(line.get("qty", 0)) - int(line.get("returned_qty", 0) or 0):
                raise ApiError("Return quantity exceeds the unreturned quantity")
            selected.append((line, qty))
        # Allocate each line's historical values proportionately. The final return of a line
        # receives any rounding remainder, so cumulative refunds never exceed the original sale.
        cur.execute("INSERT INTO sales_returns(sale_id,user_id,reason,refund_amount) VALUES(%s,%s,%s,0)",
                    (id, g.user["id"], reason))
        return_id = cur.lastrowid
        refund = Decimal("0.00")
        for line, qty in selected:
            cur.execute("""SELECT COALESCE(SUM(taxable_amount),0) AS taxable,
                                  COALESCE(SUM(cgst),0) AS cgst,COALESCE(SUM(sgst),0) AS sgst,
                                  COALESCE(SUM(igst),0) AS igst,COALESCE(SUM(tax_amount),0) AS tax
                           FROM sales_return_items WHERE sale_item_id=%s""", (line["id"],))
            returned = cur.fetchone()
            original_qty = int(line["qty"])
            old_returned = int(line.get("returned_qty", 0) or 0)
            remaining_qty = original_qty - old_returned
            parts = {}
            for key, db_key in (("taxable", "taxable_value"), ("cgst", "cgst"), ("sgst", "sgst"),
                                ("igst", "igst"), ("tax", "tax_amount")):
                original = money_decimal(line.get(db_key))
                previously = money_decimal(returned.get(key))
                if qty == remaining_qty:
                    value = original - previously
                else:
                    value = (original * Decimal(qty) / Decimal(original_qty)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                parts[key] = value
            line_refund = parts["taxable"] + parts["tax"]
            refund += line_refund
            cur.execute("""INSERT INTO sales_return_items(return_id,sale_item_id,product_id,qty,
                           taxable_amount,cgst,sgst,igst,tax_amount,refund_amount)
                           VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (return_id, line["id"], line["product_id"], qty, float(parts["taxable"]),
                         float(parts["cgst"]), float(parts["sgst"]), float(parts["igst"]),
                         float(parts["tax"]), float(line_refund)))
            cur.execute("UPDATE sale_items SET returned_qty=returned_qty+%s WHERE id=%s", (qty, line["id"]))
            if restock and line.get("product_id"):
                cur.execute("UPDATE products SET stock=stock+%s WHERE id=%s", (qty, line["product_id"]))
        refund = refund.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        return_no = f"CN-{datetime.now().strftime('%Y%m%d')}-{return_id:06d}"
        cur.execute("UPDATE sales_returns SET return_no=%s,refund_amount=%s,restocked=%s WHERE id=%s",
                    (return_no, float(refund), 1 if restock else 0, return_id))
        cur.execute("""SELECT COUNT(*) AS remaining FROM sale_items
                       WHERE sale_id=%s AND returned_qty<qty""", (id,))
        status = "partially_returned" if cur.fetchone()["remaining"] else "returned"
        cur.execute("UPDATE sales SET status=%s WHERE id=%s", (status, id))
    return {"id": return_id, "return_no": return_no, "refund_amount": float(refund), "restocked": restock}


@app.get("/api/sales/<int:id>/invoice.pdf")
@auth()
def invoice_pdf(id: int) -> Any:
    sale = readable_sale(id)
    return make_invoice_pdf(sale)


@app.get("/api/returns/<int:id>/credit-note.pdf")
@auth("admin")
def credit_note_pdf(id: int) -> Any:
    rows = select("""SELECT r.*,s.invoice_no,s.created_at AS sale_date,s.customer_id,s.place_of_supply,
                           s.customer_gstin,s.store_gstin,s.gst_state,s.user_id
                    FROM sales_returns r JOIN sales s ON s.id=r.sale_id WHERE r.id=%s""", (id,))
    if not rows:
        raise ApiError("Return not found", 404)
    ret = rows[0]
    sale = readable_sale(ret["sale_id"])
    ret["items"] = select("""SELECT ri.*,p.name AS product_name,si.hsn_code,si.tax_rate
                              FROM sales_return_items ri JOIN sale_items si ON si.id=ri.sale_item_id
                              LEFT JOIN products p ON p.id=ri.product_id WHERE ri.return_id=%s""", (id,))
    return make_invoice_pdf(sale, credit_note=ret)


def make_invoice_pdf(sale: dict[str, Any], credit_note: dict[str, Any] | None = None) -> Any:
    profile = store_profile()
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm,
                            topMargin=14*mm, bottomMargin=14*mm)
    styles = getSampleStyleSheet()
    story = []
    title = "CREDIT NOTE" if credit_note else ("TAX INVOICE" if sale.get("store_gstin") else "SALES RECEIPT")
    number = credit_note.get("return_no") if credit_note else (sale.get("invoice_no") or f"INV-{sale['id']:06d}")
    story.append(Paragraph(f"<b>{title}</b>", styles["Title"]))
    story.append(Paragraph(f"<b>{escape(profile['name'])}</b>", styles["Heading2"]))
    for text in (escape(profile["address"]), (f"Phone: {escape(profile['phone'])}" if profile["phone"] else ""),
                 (f"Email: {escape(profile['email'])}" if profile["email"] else ""),
                 (f"GSTIN: {escape(profile['gstin'])}" if profile["gstin"] else "")):
        if text:
            story.append(Paragraph(str(text).replace("&", "&amp;"), styles["Normal"]))
    story.append(Spacer(1, 5*mm))
    story.append(Paragraph(f"<b>Document:</b> {number} &nbsp;&nbsp; <b>Original invoice:</b> {sale.get('invoice_no') or sale['id']}", styles["Normal"]))
    story.append(Paragraph(f"<b>Date:</b> {escape(str(credit_note.get('created_at') if credit_note else sale.get('created_at') or '-'))} &nbsp;&nbsp; <b>Cashier:</b> {escape(str(sale.get('cashier') or '-'))}", styles["Normal"]))
    customer = sale.get("customer_name") or "Walk-in customer"
    story.append(Paragraph(f"<b>Bill to:</b> {escape(str(customer))} &nbsp;&nbsp; <b>Place of supply:</b> {escape(str(sale.get('place_of_supply') or profile['state'] or '-'))}", styles["Normal"]))
    if sale.get("customer_address"):
        story.append(Paragraph(escape(str(sale["customer_address"])), styles["Normal"]))
    customer_gstin = sale.get("customer_gstin") or sale.get("customer_profile_gstin")
    if customer_gstin:
        story.append(Paragraph(f"<b>Customer GSTIN:</b> {escape(str(customer_gstin))}", styles["Normal"]))
    if credit_note and credit_note.get("reason"):
        story.append(Paragraph(f"<b>Reason:</b> {escape(str(credit_note['reason']))}", styles["Normal"]))
    story.append(Spacer(1, 5*mm))
    header = ["Item", "HSN", "Qty", "Rate", "Taxable", "GST %", "CGST", "SGST", "IGST", "Amount"]
    rows = [header]
    total_taxable = total_cgst = total_sgst = total_igst = total_amount = Decimal("0.00")
    source_items = credit_note.get("items", []) if credit_note else sale.get("items", [])
    for item in source_items:
        if credit_note:
            taxable = money_decimal(item.get("taxable_amount")); cgst = money_decimal(item.get("cgst")); sgst = money_decimal(item.get("sgst")); igst = money_decimal(item.get("igst")); tax = money_decimal(item.get("tax_amount")); qty = item.get("qty")
            rate = item.get("tax_rate", 0); price = (taxable / Decimal(qty)) if qty else Decimal("0.00")
            amount = money_decimal(item.get("refund_amount"))
        else:
            taxable = money_decimal(item.get("taxable_value")); cgst = money_decimal(item.get("cgst")); sgst = money_decimal(item.get("sgst")); igst = money_decimal(item.get("igst")); tax = money_decimal(item.get("tax_amount")); qty = item.get("qty")
            rate = item.get("tax_rate", 0); price = money_decimal(item.get("price")); amount = taxable + tax
        rows.append([str(item.get("product_name") or "Item"), str(item.get("hsn_code") or "-"), str(qty),
                     f"{price:.2f}", f"{taxable:.2f}", f"{float(rate or 0):.2f}", f"{cgst:.2f}",
                     f"{sgst:.2f}", f"{igst:.2f}", f"{amount:.2f}"])
        total_taxable += taxable; total_cgst += cgst; total_sgst += sgst; total_igst += igst; total_amount += amount
    table = Table(rows, repeatRows=1, colWidths=[38*mm, 15*mm, 9*mm, 15*mm, 17*mm, 12*mm, 14*mm, 14*mm, 14*mm, 18*mm])
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e7efee")),
                               ("TEXTCOLOR", (0,0), (-1,0), colors.HexColor("#183c39")),
                               ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#bdc8c7")),
                               ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                               ("FONTSIZE", (0,0), (-1,-1), 7), ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
                               ("ALIGN", (2,1), (-1,-1), "RIGHT"), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f7f9f9")]),
                               ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5)]))
    story.append(table)
    story.append(Spacer(1, 5*mm))
    if credit_note:
        story.append(Paragraph(f"Taxable value reversed: Rs. {total_taxable:.2f}", styles["Normal"]))
    else:
        story.append(Paragraph(f"Subtotal: Rs. {money_decimal(sale.get('subtotal')):.2f} &nbsp;&nbsp; Discount: Rs. {money_decimal(sale.get('discount')):.2f}", styles["Normal"]))
        story.append(Paragraph(f"Taxable value: Rs. {total_taxable:.2f}", styles["Normal"]))
    story.append(Paragraph(f"CGST: Rs. {total_cgst:.2f} &nbsp;&nbsp; SGST: Rs. {total_sgst:.2f} &nbsp;&nbsp; IGST: Rs. {total_igst:.2f}", styles["Normal"]))
    story.append(Paragraph(f"<b>{'Refund due' if credit_note else 'Grand total'}: Rs. {total_amount:.2f}</b>", styles["Heading2"]))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("This document is generated by Stock Flow. Verify your GST registration, invoice series, HSN/SAC and tax treatment with your accountant before using it as a statutory tax invoice.", styles["Italic"]))
    doc.build(story)
    buffer.seek(0)
    filename = f"{number}.pdf"
    return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name=filename)


@app.get("/api/exports/<kind>.csv")
@auth("admin")
def export_csv(kind: str) -> Any:
    queries = {
        "sales": ("""SELECT s.invoice_no,s.created_at,c.name AS customer,s.status,s.subtotal,s.discount,
                         s.taxable_amount,s.cgst,s.sgst,s.igst,s.tax_total,s.total,s.place_of_supply,
                         s.customer_gstin,u.name AS cashier FROM sales s
                         LEFT JOIN customers c ON c.id=s.customer_id LEFT JOIN users u ON u.id=s.user_id
                         ORDER BY s.id DESC""", "sales-register.csv"),
        "products": ("SELECT sku,name,price,cost,stock,reorder_level,hsn_code,gst_rate FROM products ORDER BY name", "products.csv"),
        "returns": ("""SELECT r.return_no,r.created_at,s.invoice_no,r.reason,r.refund_amount,r.restocked,u.name AS processed_by
                         FROM sales_returns r JOIN sales s ON s.id=r.sale_id LEFT JOIN users u ON u.id=r.user_id
                         ORDER BY r.id DESC""", "returns-register.csv"),
    }
    if kind not in queries:
        raise ApiError("Unknown export type", 404)
    sql, filename = queries[kind]
    rows = select(sql)
    out = io.StringIO()
    if rows:
        writer = csv.DictWriter(out, fieldnames=list(rows[0].keys()), extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)
    else:
        out.write("No records\n")
    return Response("\ufeff" + out.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


# ---------- Purchase orders ----------
@app.get("/api/purchase-orders")
@auth("admin")
def po_list() -> Any:
    return select("""SELECT po.*, s.name AS supplier FROM purchase_orders po
                     JOIN suppliers s ON s.id=po.supplier_id ORDER BY po.id DESC""")


@app.post("/api/purchase-orders")
@auth("admin")
def po_add() -> Any:
    d = body()
    items = d.get("items") or []
    if not d.get("supplier_id") or not items:
        raise ApiError("Pick a supplier and add items")
    lines = [(i["product_id"], num(i.get("qty"), "Quantity", True), num(i.get("cost"), "Cost")) for i in items]
    with tx() as cur:
        total = round(sum(q * c for _, q, c in lines), 2)
        cur.execute("INSERT INTO purchase_orders(supplier_id,total) VALUES(%s,%s)", (d["supplier_id"], total))
        po_id = cur.lastrowid
        for pid, qty, cost in lines:
            cur.execute("INSERT INTO po_items(po_id,product_id,qty,cost) VALUES(%s,%s,%s,%s)",
                        (po_id, pid, qty, cost))
    return {"id": po_id}


@app.post("/api/purchase-orders/<int:id>/receive")
@auth("admin")
def po_receive(id: int) -> Any:
    with tx() as cur:
        cur.execute("SELECT * FROM purchase_orders WHERE id=%s FOR UPDATE", (id,))
        po = cur.fetchone()
        if not po or po["status"] != "pending":
            raise ApiError("Order is not pending")
        cur.execute("SELECT * FROM po_items WHERE po_id=%s", (id,))
        for i in cur.fetchall():
            cur.execute("UPDATE products SET stock=stock+%s, cost=%s WHERE id=%s",
                        (i["qty"], i["cost"], i["product_id"]))
        cur.execute("UPDATE purchase_orders SET status='received' WHERE id=%s", (id,))
    return {"ok": True}


# ---------- Reports ----------
@app.get("/api/reports")
@auth("admin")
def reports() -> Any:
    return {
        "today": select("SELECT COALESCE(SUM(s.total-COALESCE(r.refunded,0)),0) AS revenue, COUNT(*) AS orders "
                        "FROM sales s LEFT JOIN (SELECT sale_id,SUM(refund_amount) AS refunded FROM sales_returns GROUP BY sale_id) r "
                        "ON r.sale_id=s.id WHERE DATE(s.created_at)=CURDATE()")[0],
        "profit": select("SELECT COALESCE(SUM(GREATEST(si.qty-COALESCE(si.returned_qty,0),0)*(si.price-p.cost)),0) AS v "
                         "FROM sale_items si JOIN products p ON p.id=si.product_id")[0]["v"],
        "daily": list(reversed(select(
            "SELECT DATE(s.created_at) AS day,SUM(s.total-COALESCE(r.refunded,0)) AS revenue FROM sales s "
            "LEFT JOIN (SELECT sale_id,SUM(refund_amount) AS refunded FROM sales_returns GROUP BY sale_id) r ON r.sale_id=s.id "
            "GROUP BY DATE(s.created_at) ORDER BY DATE(s.created_at) DESC LIMIT 7"))),
        "top": select("SELECT p.name, SUM(GREATEST(si.qty-COALESCE(si.returned_qty,0),0)) AS qty, "
                      "SUM(GREATEST(si.qty-COALESCE(si.returned_qty,0),0)*si.price) AS revenue "
                      "FROM sale_items si JOIN products p ON p.id=si.product_id "
                      "GROUP BY p.id, p.name HAVING qty>0 ORDER BY qty DESC LIMIT 5"),
        "low": select("SELECT name,stock,reorder_level FROM products "
                      "WHERE stock<=reorder_level ORDER BY stock"),
    }


# ---------- Safe, idempotent billing schema migration ----------
def ensure_billing_schema() -> None:
    """Add the new billing columns/tables without replacing existing inventory or sales data."""
    column_additions = {
        "products": {
            "hsn_code": "VARCHAR(20) NULL",
            "gst_rate": "DECIMAL(5,2) NOT NULL DEFAULT 0.00",
        },
        "customers": {
            "gstin": "VARCHAR(20) NULL",
            "state": "VARCHAR(100) NULL",
            "address": "TEXT NULL",
        },
        "sales": {
            "invoice_no": "VARCHAR(40) NULL",
            "subtotal": "DECIMAL(12,2) NOT NULL DEFAULT 0.00",
            "taxable_amount": "DECIMAL(12,2) NOT NULL DEFAULT 0.00",
            "cgst": "DECIMAL(12,2) NOT NULL DEFAULT 0.00",
            "sgst": "DECIMAL(12,2) NOT NULL DEFAULT 0.00",
            "igst": "DECIMAL(12,2) NOT NULL DEFAULT 0.00",
            "tax_total": "DECIMAL(12,2) NOT NULL DEFAULT 0.00",
            "place_of_supply": "VARCHAR(100) NULL",
            "customer_gstin": "VARCHAR(20) NULL",
            "store_gstin": "VARCHAR(20) NULL",
            "gst_state": "VARCHAR(100) NULL",
            "status": "VARCHAR(30) NOT NULL DEFAULT 'completed'",
        },
        "sale_items": {
            "hsn_code": "VARCHAR(20) NULL",
            "tax_rate": "DECIMAL(5,2) NOT NULL DEFAULT 0.00",
            "discount_amount": "DECIMAL(12,2) NOT NULL DEFAULT 0.00",
            "taxable_value": "DECIMAL(12,2) NOT NULL DEFAULT 0.00",
            "cgst": "DECIMAL(12,2) NOT NULL DEFAULT 0.00",
            "sgst": "DECIMAL(12,2) NOT NULL DEFAULT 0.00",
            "igst": "DECIMAL(12,2) NOT NULL DEFAULT 0.00",
            "tax_amount": "DECIMAL(12,2) NOT NULL DEFAULT 0.00",
            "returned_qty": "INT NOT NULL DEFAULT 0",
        },
    }
    c = connect()
    try:
        cur = c.cursor()
        for table, columns in column_additions.items():
            cur.execute(f"SHOW TABLES LIKE %s", (table,))
            if not cur.fetchone():
                raise RuntimeError(f"Required table '{table}' is missing. Restore the original store database schema first.")
            for column, definition in columns.items():
                cur.execute(f"SHOW COLUMNS FROM `{table}` LIKE %s", (column,))
                if not cur.fetchone():
                    try:
                        cur.execute(f"ALTER TABLE `{table}` ADD COLUMN `{column}` {definition}")
                    except pymysql.MySQLError as migration_err:
                        # Multiple Gunicorn workers may start together and race on the same DDL.
                        if not migration_err.args or migration_err.args[0] != 1060:
                            raise
        cur.execute("""CREATE TABLE IF NOT EXISTS sales_returns (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            sale_id BIGINT NOT NULL,
            user_id BIGINT NULL,
            return_no VARCHAR(40) NULL UNIQUE,
            reason VARCHAR(250) NULL,
            refund_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
            restocked TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_sales_returns_sale (sale_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
        cur.execute("""CREATE TABLE IF NOT EXISTS sales_return_items (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            return_id BIGINT NOT NULL,
            sale_item_id BIGINT NOT NULL,
            product_id BIGINT NULL,
            qty INT NOT NULL,
            taxable_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
            cgst DECIMAL(12,2) NOT NULL DEFAULT 0.00,
            sgst DECIMAL(12,2) NOT NULL DEFAULT 0.00,
            igst DECIMAL(12,2) NOT NULL DEFAULT 0.00,
            tax_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
            refund_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
            INDEX idx_return_items_return (return_id),
            INDEX idx_return_items_sale_item (sale_item_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
        # Old sales are retained. Backfill their original untaxed line values so old receipts
        # remain readable and a later return can refund the historical sale amount accurately.
        cur.execute("SELECT id,created_at,total,discount,subtotal FROM sales ORDER BY id")
        old_sales = cur.fetchall()
        for row in old_sales:
            created = row.get("created_at")
            if hasattr(created, "strftime"):
                stamp = created.strftime("%Y%m%d")
            else:
                try:
                    stamp = datetime.fromisoformat(str(created)).strftime("%Y%m%d")
                except (TypeError, ValueError):
                    stamp = datetime.now().strftime("%Y%m%d")
            cur.execute("UPDATE sales SET invoice_no=COALESCE(NULLIF(invoice_no,''),%s) WHERE id=%s",
                        (f"INV-{stamp}-{int(row['id']):06d}", row["id"]))
            if money_decimal(row.get("subtotal")) == Decimal("0.00"):
                cur.execute("SELECT id,qty,price FROM sale_items WHERE sale_id=%s ORDER BY id", (row["id"],))
                lines = cur.fetchall()
                gross_total = sum((money_decimal(line["price"]) * int(line["qty"]) for line in lines), Decimal("0.00"))
                discount_left = min(money_decimal(row.get("discount")), gross_total)
                for idx, line in enumerate(lines):
                    gross = (money_decimal(line["price"]) * int(line["qty"])).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                    if idx == len(lines) - 1:
                        line_discount = discount_left
                    elif gross_total:
                        line_discount = (min(money_decimal(row.get("discount")), gross_total) * gross / gross_total).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                        line_discount = min(line_discount, discount_left)
                    else:
                        line_discount = Decimal("0.00")
                    discount_left -= line_discount
                    cur.execute("""UPDATE sale_items si LEFT JOIN products p ON p.id=si.product_id
                                   SET si.hsn_code=p.hsn_code,si.tax_rate=0,si.discount_amount=%s,
                                       si.taxable_value=%s,si.cgst=0,si.sgst=0,si.igst=0,si.tax_amount=0
                                   WHERE si.id=%s""", (float(line_discount), float(gross-line_discount), line["id"]))
                cur.execute("""UPDATE sales SET subtotal=%s,taxable_amount=%s,cgst=0,sgst=0,igst=0,tax_total=0,
                               status=COALESCE(status,'completed') WHERE id=%s""",
                            (float(gross_total), float(gross_total - min(money_decimal(row.get("discount")), gross_total)), row["id"]))
        c.commit()
    finally:
        c.close()


try:
    ensure_billing_schema()
except Exception as migration_error:
    app.logger.exception("Billing schema migration did not complete: %s", migration_error)


# ---------- First-run admin ----------
def seed_admin() -> None:
    try:
        if not select("SELECT id FROM users LIMIT 1"):
            execute("INSERT INTO users(username,name,password,role) VALUES(%s,%s,%s,%s)",
                    ("admin", "Administrator", hash_pw("admin123"), "admin"))
            print("Created default login: admin / admin123 (change it!)")
    except Exception as err:
        print("Could not set up the admin user. Check the DB_* values in .env and that schema.sql was run.\n", err)


seed_admin()

if __name__ == "__main__":
    app.run(port=int(os.getenv("PORT", "3000")), debug=os.getenv("FLASK_DEBUG") == "1")