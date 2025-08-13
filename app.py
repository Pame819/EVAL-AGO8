import os
import sqlite3
import requests
from flask import Flask, request, session, redirect, render_template_string, jsonify, make_response

app = Flask(__name__)
app.secret_key = "secret"
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=False,
    SESSION_COOKIE_SAMESITE=None,
)

DB_PATH = "techshop.db"

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(DB_PATH):
        conn = db()
        cur = conn.cursor()
        cur.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        );

        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price REAL
        );

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            qty INTEGER,
            total REAL
        );

        INSERT INTO users (email, password, role) VALUES
            ('cliente@test.com','123456','user'),
            ('admin@techshop.com','admin123','admin');

        INSERT INTO products (name, price) VALUES
            ('Laptop Pro 14', 1499.0),
            ('Mouse Inalámbrico', 29.9),
            ('Teclado Mecánico', 89.0);
        """)
        conn.commit()
        conn.close()

init_db()

BASE_HTML = """
<!doctype html>
<title>TechShop S.A. - Demo</title>
<h1>TechShop S.A. (Demo vulnerable)</h1>
<p>
  <a href="/">Inicio</a> |
  {% if session.get('user') %}
    Usuario: {{session['user']['email']}} ({{session['user']['role']}})
    | <a href="/logout">Salir</a>
  {% else %}
    <a href="/login">Login</a> | <a href="/register">Registro</a>
  {% endif %}
  | <a href="/tienda">Tienda</a> | <a href="/admin">Admin</a>
</p>
<hr/>
{{ body|safe }}
"""

def page(body_tmpl: str, **ctx):
    body = render_template_string(body_tmpl, session=session, **ctx)
    return render_template_string(BASE_HTML, body=body, session=session)

@app.route("/")
def index():
    return page("""
        <p>Portal interno de pruebas de seguridad OWASP Top 10.</p>
        <ul>
          <li>/tienda - Lista de productos</li>
          <li>/buscar?q= - Buscador </li>
          <li>/fetch?url= - URL arbitraria</li>
          <li>/admin - Panel administrativo</li>
        </ul>
    """)

@app.route("/tienda")
def tienda():
    con = db(); cur = con.cursor()
    cur.execute("SELECT id, name, price FROM products")
    prods = cur.fetchall()
    return page("""
        <h2>Tienda</h2>
        <form method="get" action="/buscar">
          <input name="q" placeholder="buscar...">
          <button>Buscar</button>
        </form>
        <ul>
        {% for p in prods %}
          <li>#{{p['id']}} - {{p['name']}} - ${{p['price']}}
            [<a href="/product/{{p['id']}}">ver</a>]
          </li>
        {% endfor %}
        </ul>
    """, prods=prods)

@app.route("/product/<int:pid>")
def product(pid):
    con = db(); cur = con.cursor()
    cur.execute("SELECT id, name, price FROM products WHERE id=?", (pid,))
    p = cur.fetchone()
    if not p:
        return "No existe", 404
    return page("""
        <h3>Producto #{{p['id']}} - {{p['name']}} - ${{p['price']}}</h3>
        <form method="post" action="/order">
          <input type="hidden" name="product_id" value="{{p['id']}}">
          Cantidad (permite negativos 🤕):
          <input name="qty" value="1" type="number">
          <button>Comprar</button>
        </form>
    """, p=p)

@app.route("/order", methods=["POST"])
def order():
    if not session.get("user"):
        return redirect("/login")
    user_id = session["user"]["id"]
    product_id = int(request.form.get("product_id", "0"))
    qty = int(request.form.get("qty", "1"))
    con = db(); cur = con.cursor()
    cur.execute("SELECT price FROM products WHERE id=?", (product_id,))
    row = cur.fetchone()
    if not row:
        return "Producto inválido", 400
    total = row["price"] * qty
    cur.execute("INSERT INTO orders (user_id, product_id, qty, total) VALUES (?,?,?,?)",
                (user_id, product_id, qty, total))
    con.commit()
    return page(f"""
        <p>Orden generada. qty={qty}, total={total:.2f}</p>
    """)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","")
        password = request.form.get("password","")
        con = db(); cur = con.cursor()
        query = f"SELECT id,email,password,role FROM users WHERE email='{email}' AND password='{password}'"
        row = cur.execute(query).fetchone()
        if row:
            session["user"] = {"id": row["id"], "email": row["email"], "role": row["role"]}
            return redirect("/")
        return page("<p>Credenciales inválidas</p>")
    return page("""
        <h2>Login</h2>
        <form method="post">
          <p>Email: <input name="email" value="cliente@test.com"></p>
          <p>Password: <input name="password" value="123456" type="password"></p>
          <button>Ingresar</button>
        </form>
        <p><a href="/forgot?email=admin@techshop.com">¿Olvidó su contraseña?</a></p>
    """)

@app.route("/forgot")
def forgot():
    email = request.args.get("email","")
    token = "reset-"+email.replace("@","-")
    return page(f"Se envió un enlace de reseteo con token: {token} (demo insegura)")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email","")
        password = request.form.get("password","")
        con = db(); cur = con.cursor()
        try:
            cur.execute("INSERT INTO users (email,password) VALUES (?,?)", (email,password))
            con.commit()
            return redirect("/login")
        except sqlite3.IntegrityError:
            return page("Email ya existe")
    return page("""
        <h2>Registro</h2>
        <form method="post">
          <p>Email: <input name="email"></p>
          <p>Password: <input name="password" type="password"></p>
          <button>Crear</button>
        </form>
    """)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/buscar")
def buscar():
    q = request.args.get("q","")
    con = db(); cur = con.cursor()
    query = f"SELECT id,name,price FROM products WHERE name LIKE '%{q}%'"
    rows = cur.execute(query).fetchall()
    return page("""
        <h2>Resultados para "{{q}}"</h2>
        <ul>
        {% for r in rows %}
          <li>#{{r['id']}} - {{r['name']}} - ${{r['price']}}</li>
        {% endfor %}
        </ul>
        <p>Query ejecutada (insegura): {{raw_query}}</p>
    """, q=q, rows=rows, raw_query=query)

@app.route("/admin")
def admin():
    as_role = request.args.get("as")
    if as_role == "admin":
        fake_user = {"id": -1, "email": "spoof@attacker", "role": "admin"}
        session["user"] = fake_user
    user = session.get("user")
    if not user or user.get("role") != "admin":
        return "Prohibido. Solo admin.", 403
    con = db(); cur = con.cursor()
    users = cur.execute("SELECT id,email,password,role FROM users").fetchall()
    return page("""
        <h2>Panel Admin</h2>
        <p>Listado de usuarios :</p>
        <ul>
        {% for u in users %}
          <li>#{{u['id']}} - {{u['email']}} - {{u['password']}} - {{u['role']}}</li>
        {% endfor %}
        </ul>
        <p><a href="/import_catalog?url=http://localhost:5000/sample.json">Importar catálogo (inseguro)</a></p>
    """, users=users)

@app.route("/fetch")
def fetch():
    url = request.args.get("url","http://127.0.0.1:5000/")
    try:
        r = requests.get(url, timeout=5)
        resp = make_response(r.text, 200)
        return resp
    except Exception as e:
        return f"Error al fetch: {e}", 500

@app.route("/import_catalog")
def import_catalog():
    url = request.args.get("url","")
    if not url:
        return "Proporcione ?url=", 400
    try:
        data = requests.get(url, timeout=5).json()
        con = db(); cur = con.cursor()
        inserted = 0
        for item in data:
            cur.execute(
                "INSERT INTO products (name, price) VALUES (?,?)",
                (item.get("name","item"), float(item.get("price", 1.0)))
            )
            inserted += 1
        con.commit()
        return page(f"Importados {inserted} items desde {url}")
    except Exception as e:
        return page(f"Fallo importación: {e}")

@app.route("/healthz")
def healthz():
    return jsonify({"status":"ok"})

SAMPLE_JSON = [{"name":"USB-C Hub 7-en-1","price":39.9},{"name":"Monitor 27 IPS","price":179.0}]

@app.route("/sample.json")
def sample_json():
    return jsonify(SAMPLE_JSON)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5010, debug=True)