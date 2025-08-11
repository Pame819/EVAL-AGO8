from flask import Flask, request, render_template_string, redirect, url_for, make_response, session, jsonify
import sqlite3
import os
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'clave_pass'

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Portal Universitario - Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; }
        .error { color: red; margin-top: 10px; }
        .debug { background: #f8f9fa; padding: 10px; margin: 10px 0; border-left: 4px solid #007bff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎓 Portal Universitario</h1>
        <h2>Iniciar Sesión</h2>
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Usuario:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Contraseña:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Iniciar Sesión</button>
        </form>
        
        {% if error %}
        <div class="error">{{ error|safe }}</div>
        {% endif %}
        
        <div class="debug">
            <strong>Modo Desarrollo:</strong> Credenciales de prueba disponibles<br>
            <em>admin:admin123 | profesor:profesor123 | estudiante:123456</em>
        </div>
        
        <hr>
        <p><a href="/register">Registrarse</a> | <a href="/contact">Contacto</a> | <a href="/admin">Panel Admin</a></p>
    </div>
    
    <script>
        var csrfToken = "{{ csrf_token if csrf_token else 'no_token' }}";
        console.log("Debug: CSRF Token =", csrfToken);
    </script>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - Portal Universitario</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        .user-info { background: #e7f3ff; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 15px; color: #007bff; text-decoration: none; }
        .search-box { margin: 20px 0; }
        .search-box input { padding: 8px; width: 300px; }
        .search-box button { padding: 8px 15px; background: #28a745; color: white; border: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎓 Dashboard Universitario</h1>
        
        <div class="user-info">
            <strong>Bienvenido:</strong> {{ username }}<br>
            <strong>Rol:</strong> {{ role }}<br>
            <strong>Última conexión:</strong> {{ last_login }}
        </div>
        
        <div class="nav">
            <a href="/profile?user={{ username }}">Mi Perfil</a>
            <a href="/grades?student_id={{ user_id }}">Calificaciones</a>
            <a href="/documents">Documentos</a>
            {% if role == 'admin' %}
            <a href="/admin/users">Gestión Usuarios</a>
            <a href="/admin/reports">Reportes</a>
            {% endif %}
            <a href="/logout">Cerrar Sesión</a>
        </div>
        
        <h3>Búsqueda de Estudiantes</h3>
        <div class="search-box">
            <form method="GET" action="/search">
                <input type="text" name="query" placeholder="Buscar por nombre o ID..." value="{{ search_query }}">
                <button type="submit">Buscar</button>
            </form>
        </div>
        
        {% if search_results %}
        <h4>Resultados de búsqueda:</h4>
        <div>{{ search_results|safe }}</div>
        {% endif %}
        
        <h3>Comentarios del Sistema</h3>
        <form method="POST" action="/comment">
            <textarea name="comment" placeholder="Escribe tu comentario..." style="width:100%; height:80px;"></textarea><br><br>
            <button type="submit">Enviar Comentario</button>
        </form>
        
        {% if comments %}
        <div style="margin-top: 20px;">
            {% for comment in comments %}
            <div style="border: 1px solid #ddd; padding: 10px; margin: 5px 0;">
                {{ comment|safe }}
            </div>
            {% endfor %}
        </div>
        {% endif %}
    </div>
    
    <script>
        function showUserData() {
            console.log("User session data:", {
                username: "{{ username }}",
                role: "{{ role }}",
                sessionId: "{{ session_id }}",
                internalId: "{{ user_id }}"
            });
        }
        
        if (window.location.hostname === 'localhost') {
            showUserData();
        }
    </script>
</body>
</html>
'''

CONTACT_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Contacto - Portal Universitario</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📧 Formulario de Contacto</h1>
        
        <form method="POST" action="/contact">
            <div class="form-group">
                <label for="name">Nombre:</label>
                <input type="text" id="name" name="name" required>
            </div>
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="subject">Asunto:</label>
                <input type="text" id="subject" name="subject" required>
            </div>
            <div class="form-group">
                <label for="message">Mensaje:</label>
                <textarea id="message" name="message" rows="5" required></textarea>
            </div>
            <button type="submit">Enviar Mensaje</button>
        </form>
        
        {% if success %}
        <div style="color: green; margin-top: 15px;">
            ✅ Mensaje enviado correctamente
        </div>
        {% endif %}
        
        <hr>
        <p><a href="/">Volver al inicio</a></p>
    </div>
</body>
</html>
'''

def init_db():
    conn = sqlite3.connect('university.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, email TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS comments
                 (id INTEGER PRIMARY KEY, username TEXT, comment TEXT, timestamp TEXT)''')
    
    users = [
        ('admin', 'admin123', 'admin', 'admin@universidad.edu'),
        ('profesor', 'profesor123', 'profesor', 'profesor@universidad.edu'),
        ('estudiante', '123456', 'estudiante', 'estudiante@universidad.edu'),
        ('juan_perez', 'password', 'estudiante', 'juan@universidad.edu'),
        ('maria_garcia', '12345', 'estudiante', 'maria@universidad.edu')
    ]
    
    for user in users:
        c.execute("INSERT OR IGNORE INTO users VALUES (NULL, ?, ?, ?, ?)", user)
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('university.db')
        c = conn.cursor()
        
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            c.execute(query)
            user = c.fetchone()
            
            if user:
                session['username'] = user[1]
                session['role'] = user[3]
                session['user_id'] = user[0]
                session['session_id'] = hashlib.md5(f"{user[1]}{datetime.now()}".encode()).hexdigest()
                
                resp = make_response(redirect(url_for('dashboard')))
                resp.set_cookie('user_session', session['session_id'])
                resp.set_cookie('username', username)
                return resp
            else:
                error = f"Credenciales incorrectas para usuario: {username}"
                return render_template_string(LOGIN_TEMPLATE, error=error)
                
        except Exception as e:
            error = f"Error en la base de datos: {str(e)}"
            return render_template_string(LOGIN_TEMPLATE, error=error)
        finally:
            conn.close()
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('university.db')
    c = conn.cursor()
    c.execute("SELECT comment FROM comments ORDER BY timestamp DESC LIMIT 5")
    comments = [row[0] for row in c.fetchall()]
    conn.close()
    
    search_query = request.args.get('query', '')
    search_results = ""
    
    return render_template_string(DASHBOARD_TEMPLATE, 
                                username=session['username'],
                                role=session['role'],
                                user_id=session['user_id'],
                                session_id=session['session_id'],
                                last_login=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                search_query=search_query,
                                search_results=search_results,
                                comments=comments)

@app.route('/search')
def search():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    query = request.args.get('query', '')
    search_results = ""
    
    if query:
        conn = sqlite3.connect('university.db')
        c = conn.cursor()
        
        sql_query = f"SELECT username, email FROM users WHERE username LIKE '%{query}%' OR email LIKE '%{query}%'"
        try:
            c.execute(sql_query)
            results = c.fetchall()
            
            if results:
                search_results = "<ul>"
                for result in results:
                    search_results += f"<li><strong>{result[0]}</strong> - {result[1]}</li>"
                search_results += "</ul>"
            else:
                search_results = f"No se encontraron resultados para: {query}"
                
        except Exception as e:
            search_results = f"Error en búsqueda: {str(e)}"
        finally:
            conn.close()
    
    return render_template_string(DASHBOARD_TEMPLATE, 
                                username=session['username'],
                                role=session['role'],
                                user_id=session['user_id'],
                                session_id=session['session_id'],
                                last_login=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                search_query=query,
                                search_results=search_results,
                                comments=[])

@app.route('/comment', methods=['POST'])
def add_comment():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    comment = request.form['comment']
    
    conn = sqlite3.connect('university.db')
    c = conn.cursor()
    c.execute("INSERT INTO comments VALUES (NULL, ?, ?, ?)", 
              (session['username'], comment, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard'))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        
        return render_template_string(CONTACT_TEMPLATE, success=True)
    
    return render_template_string(CONTACT_TEMPLATE)

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_param = request.args.get('user', session['username'])
    
    conn = sqlite3.connect('university.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (user_param,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        profile_html = f'''
        <html>
        <head><title>Perfil de Usuario</title></head>
        <body style="font-family: Arial; margin: 40px;">
            <h1>👤 Perfil de Usuario</h1>
            <p><strong>ID:</strong> {user_data[0]}</p>
            <p><strong>Usuario:</strong> {user_data[1]}</p>
            <p><strong>Rol:</strong> {user_data[3]}</p>
            <p><strong>Email:</strong> {user_data[4]}</p>
            <hr>
            <p><a href="/dashboard">Volver al Dashboard</a></p>
        </body>
        </html>
        '''
        return profile_html
    else:
        return "Usuario no encontrado", 404

@app.route('/grades')
def grades():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    student_id = request.args.get('student_id', session['user_id'])
    
    grades_data = {
        '1': [('Ciberseguridad', 85), ('Base de Datos', 92), ('Programación', 78)],
        '2': [('Matemáticas', 88), ('Física', 76), ('Química', 91)],
        '3': [('Historia', 89), ('Literatura', 94), ('Filosofía', 82)],
        '4': [('Inglés', 87), ('Francés', 79), ('Alemán', 85)],
        '5': [('Economía', 90), ('Contabilidad', 83), ('Marketing', 88)]
    }
    
    grades = grades_data.get(str(student_id), [('No hay calificaciones', 0)])
    
    grades_html = f'''
    <html>
    <head>
        <title>Calificaciones - Portal Universitario</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f8f9fa; }}
            .student-info {{ background: #e7f3ff; padding: 15px; border-radius: 4px; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📊 Calificaciones Estudiantiles</h1>
            
            <div class="student-info">
                <strong>ID de Estudiante:</strong> {student_id}<br>
                <strong>Consultado por:</strong> {session['username']}<br>
                <strong>Fecha de consulta:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </div>
            
            <table>
                <tr>
                    <th>Materia</th>
                    <th>Calificación</th>
                    <th>Estado</th>
                </tr>
    '''
    
    for subject, grade in grades:
        status = "Aprobado" if grade >= 70 else "Reprobado"
        status_color = "green" if grade >= 70 else "red"
        grades_html += f'''
                <tr>
                    <td>{subject}</td>
                    <td>{grade}</td>
                    <td style="color: {status_color}; font-weight: bold;">{status}</td>
                </tr>
        '''
    
    grades_html += '''
            </table>
            
            <div style="margin-top: 20px;">
                <h3>🔍 Consultar Otras Calificaciones</h3>
                <form method="GET" action="/grades">
                    <label>ID de Estudiante:</label>
                    <input type="number" name="student_id" placeholder="Ej: 1, 2, 3..." style="padding: 8px; margin: 0 10px;">
                    <button type="submit" style="padding: 8px 15px; background: #007bff; color: white; border: none; border-radius: 4px;">Consultar</button>
                </form>
                <small style="color: #666;">Prueba con IDs: 1, 2, 3, 4, 5</small>
            </div>
            
            <hr>
            <p><a href="/dashboard">← Volver al Dashboard</a></p>
        </div>
        
        <script>
            window.studentData = {
                currentId: ''' + str(student_id) + ''',
                accessedBy: "''' + session['username'] + '''",
                userRole: "''' + session['role'] + '''",
                sessionId: "''' + session.get('session_id', '') + '''"
            };
            console.log("Student data loaded:", window.studentData);
        </script>
    </body>
    </html>
    '''
    return grades_html

@app.route('/documents')
def documents():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    doc_type = request.args.get('type', 'general')
    doc_id = request.args.get('id', '')
    
    documents_html = f'''
    <html>
    <head>
        <title>Documentos - Portal Universitario</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
            .doc-category {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 4px; }}
            .doc-item {{ margin: 10px 0; padding: 10px; background: #f8f9fa; border-left: 4px solid #007bff; }}
            .search-box {{ margin: 20px 0; padding: 15px; background: #f0f0f0; border-radius: 4px; }}
            .sensitive {{ color: red; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📁 Centro de Documentos</h1>
            
            <div class="search-box">
                <h3>🔍 Buscar Documentos</h3>
                <form method="GET" action="/documents">
                    <label>Tipo de documento:</label>
                    <select name="type" style="padding: 8px; margin: 0 10px;">
                        <option value="general" {"selected" if doc_type == "general" else ""}>General</option>
                        <option value="admin" {"selected" if doc_type == "admin" else ""}>Administrativos</option>
                        <option value="confidential" {"selected" if doc_type == "confidential" else ""}>Confidenciales</option>
                        <option value="backup" {"selected" if doc_type == "backup" else ""}>Backups</option>
                    </select>
                    <label>ID de documento:</label>
                    <input type="text" name="id" value="{doc_id}" placeholder="../config.txt" style="padding: 8px; margin: 0 10px;">
                    <button type="submit" style="padding: 8px 15px; background: #28a745; color: white; border: none; border-radius: 4px;">Buscar</button>
                </form>
            </div>
            
            <div class="doc-category">
                <h3>📋 Documentos Disponibles - Tipo: {doc_type}</h3>
    '''
    
    if doc_type == "general":
        docs = [
            ("manual_estudiante.pdf", "Manual del Estudiante 2024"),
            ("calendario_academico.pdf", "Calendario Académico"),
            ("reglamento.pdf", "Reglamento Institucional")
        ]
    elif doc_type == "admin":
        docs = [
            ("usuarios_activos.xlsx", "Lista de Usuarios Activos"),
            ("estadisticas_acceso.csv", "Estadísticas de Acceso"),
            ("configuracion_sistema.txt", "Configuración del Sistema")
        ]
    elif doc_type == "confidential":
        docs = [
            ("passwords_backup.txt", "🔒 Backup de Contraseñas"),
            ("database_credentials.env", "🔒 Credenciales de Base de Datos"),
            ("server_keys.pem", "🔒 Claves del Servidor")
        ]
    elif doc_type == "backup":
        docs = [
            ("university_backup_2024.sql", "Backup Base de Datos"),
            ("config_backup.tar.gz", "Backup Configuraciones"),
            ("logs_sistema.log", "Logs del Sistema")
        ]
    else:
        docs = [("error.txt", "Tipo de documento no válido")]
    
    for filename, description in docs:
        is_sensitive = doc_type in ["confidential", "backup"]
        sensitive_class = 'class="sensitive"' if is_sensitive else ''
        
        documents_html += f'''
                <div class="doc-item">
                    <strong {sensitive_class}>{filename}</strong><br>
                    <small>{description}</small><br>
                    <a href="/download?file={filename}&type={doc_type}">📥 Descargar</a>
                    {"<span class='sensitive'> ⚠️ DOCUMENTO SENSIBLE</span>" if is_sensitive else ""}
                </div>
        '''
    
    documents_html += f'''
            </div>
            
            {"<div class='sensitive'>⚠️ ADVERTENCIA: Está accediendo a documentos confidenciales sin autorización adecuada</div>" if doc_type == "confidential" else ""}
            
           
            
            <hr>
            <p><a href="/dashboard">← Volver al Dashboard</a></p>
        </div>
        
        <script>
            const systemPaths = {{
                documentRoot: "/var/www/documents/",
                configPath: "/etc/university/config/",
                backupPath: "/opt/backups/university/",
                logPath: "/var/log/university.log"
            }};
            
            console.log("System paths loaded:", systemPaths);
            console.log("Current user access level:", "{session['role']}");
        </script>
    </body>
    </html>
    '''
    return documents_html

@app.route('/admin')
def admin_panel():
    admin_html = '''
    <html>
    <head><title>Panel de Administración</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h1>🔧 Panel de Administración</h1>
        <h3>Rutas administrativas:</h3>
        <ul>
            <li><a href="/admin/users">Gestión de Usuarios</a></li>
            <li><a href="/admin/backup">Backup de Base de Datos</a></li>
            <li><a href="/admin/logs">Logs del Sistema</a></li>
            <li><a href="/admin/config">Configuración</a></li>
        </ul>
        <hr>
        <p><a href="/">Volver al inicio</a></p>
    </body>
    </html>
    '''
    return admin_html

@app.route('/admin/users')
def admin_users():
    conn = sqlite3.connect('university.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()
    
    users_html = '''
    <html>
    <head><title>Gestión de Usuarios</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h1>👥 Gestión de Usuarios</h1>
        <table border="1" style="border-collapse: collapse; width: 100%;">
            <tr>
                <th>ID</th><th>Usuario</th><th>Contraseña</th><th>Rol</th><th>Email</th>
            </tr>
    '''
    
    for user in users:
        users_html += f"<tr><td>{user[0]}</td><td>{user[1]}</td><td>{user[2]}</td><td>{user[3]}</td><td>{user[4]}</td></tr>"
    
    users_html += '''
        </table>
        <hr>
        <p><a href="/admin">Volver al Panel Admin</a></p>
    </body>
    </html>
    '''
    return users_html

@app.route('/admin/reports')
def admin_reports():
    reports_html = '''
    <html>
    <head>
        <title>Reportes Administrativos</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
            .report-section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 4px; }
            .metric { display: inline-block; margin: 10px; padding: 15px; background: #f8f9fa; border-radius: 4px; min-width: 120px; text-align: center; }
            .sensitive-data { background: #ffe6e6; padding: 15px; border-left: 4px solid #dc3545; margin: 15px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📊 Reportes Administrativos del Sistema</h1>
            
            <div class="report-section">
                <h3>📈 Métricas Generales</h3>
                <div class="metric">
                    <strong>Usuarios Activos</strong><br>
                    247 usuarios
                </div>
                <div class="metric">
                    <strong>Sesiones Hoy</strong><br>
                    89 sesiones
                </div>
                <div class="metric">
                    <strong>Intentos de Login</strong><br>
                    156 intentos
                </div>
                <div class="metric">
                    <strong>Errores 404</strong><br>
                    23 errores
                </div>
            </div>
            
            <div class="report-section">
                <h3>🔐 Reporte de Seguridad</h3>
                <div class="sensitive-data">
                    <strong>⚠️ ALERTAS DE SEGURIDAD:</strong><br>
                    • 15 intentos de SQL injection detectados en las últimas 24h<br>
                    • 8 intentos de acceso no autorizado al panel admin<br>
                    • 3 usuarios con contraseñas débiles: admin, profesor, estudiante<br>
                    • 12 cookies de sesión sin expirar correctamente
                </div>
            </div>
            
            <div class="report-section">
                <h3>👥 Usuarios más Activos</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr style="background: #f8f9fa;">
                        <th style="padding: 10px; border: 1px solid #ddd;">Usuario</th>
                        <th style="padding: 10px; border: 1px solid #ddd;">Último Acceso</th>
                        <th style="padding: 10px; border: 1px solid #ddd;">IP</th>
                        <th style="padding: 10px; border: 1px solid #ddd;">Sesiones</th>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;">admin</td>
                        <td style="padding: 10px; border: 1px solid #ddd;">2024-08-08 14:32:15</td>
                        <td style="padding: 10px; border: 1px solid #ddd;">192.168.1.100</td>
                        <td style="padding: 10px; border: 1px solid #ddd;">45</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;">profesor</td>
                        <td style="padding: 10px; border: 1px solid #ddd;">2024-08-08 13:15:22</td>
                        <td style="padding: 10px; border: 1px solid #ddd;">10.0.0.25</td>
                        <td style="padding: 10px; border: 1px solid #ddd;">23</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;">estudiante</td>
                        <td style="padding: 10px; border: 1px solid #ddd;">2024-08-08 12:45:33</td>
                        <td style="padding: 10px; border: 1px solid #ddd;">172.16.0.50</td>
                        <td style="padding: 10px; border: 1px solid #ddd;">18</td>
                    </tr>
                </table>
            </div>
            
            <div class="sensitive-data">
                <strong>🔑 CREDENCIALES DE SERVICIO (CONFIDENCIAL):</strong><br>
                • Database: root / admin123<br>
                • FTP Server: backup_user / backup2024!<br>
                • Email Service: noreply@universidad.edu / smtp_pass_2024<br>
                • API Key: sk_live_51H7xQaE2eZvKYlo0C...
            </div>
            
            <hr>
            <p><a href="/admin">← Volver al Panel Admin</a></p>
        </div>
        
        <script>
            window.adminData = {
                serverStats: {
                    uptime: "15 days, 7 hours",
                    memoryUsage: "73%",
                    diskUsage: "45%",
                    activeConnections: 89
                },
                securityFlags: {
                    sqlInjectionAttempts: 15,
                    bruteForceAttempts: 8,
                    vulnerableUsers: ["admin", "profesor", "estudiante"]
                },
                internalIPs: ["192.168.1.100", "10.0.0.25", "172.16.0.50"]
            };
            
            console.log("Admin dashboard data loaded:", window.adminData);
        </script>
    </body>
    </html>
    '''
    return reports_html

@app.route('/download')
def download_file():
    filename = request.args.get('file', '')
    file_type = request.args.get('type', 'general')
    
    download_html = f'''
    <html>
    <head><title>Descarga de Archivo</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h1>📥 Descargando Archivo</h1>
        <p><strong>Archivo:</strong> {filename}</p>
        <p><strong>Tipo:</strong> {file_type}</p>
        <p><strong>Ruta del sistema:</strong> /var/www/documents/{file_type}/{filename}</p>
        
        {"<div style='color: red; font-weight: bold;'>⚠️ ADVERTENCIA: Este archivo contiene información sensible</div>" if file_type == "confidential" else ""}
        
        <div style="margin: 20px 0; padding: 15px; background: #f0f0f0; border-radius: 4px;">
            <strong>Contenido del archivo (preview):</strong><br><br>
            <code>
    '''
    
    if filename == "passwords_backup.txt":
        download_html += '''
admin:admin123
profesor:profesor123
estudiante:123456
root:toor
backup_user:backup2024!
        '''
    elif filename == "database_credentials.env":
        download_html += '''
DB_HOST=localhost
DB_USER=root
DB_PASS=admin123
DB_NAME=university
API_KEY=sk_live_51H7xQaE2eZvKYlo0C...
        '''
    else:
        download_html += f"Contenido del archivo {filename}..."
    
    download_html += '''
            </code>
        </div>
        
        <p><a href="/documents">← Volver a Documentos</a></p>
    </body>
    </html>
    '''
    
    return download_html

@app.route('/api/user/<int:user_id>')
def api_user(user_id):
    conn = sqlite3.connect('university.db')
    c = conn.cursor()
    c.execute("SELECT username, email, role FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'username': user[0],
            'email': user[1],
            'role': user[2],
            'api_version': '1.0',
            'server_info': 'Ubuntu 20.04 - Apache/2.4.41'
        })
    else:
        return jsonify({'error': 'Usuario no encontrado'}), 404

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('user_session', '', expires=0)
    resp.set_cookie('username', '', expires=0)
    return resp

@app.route('/debug/session')
def debug_session():
    return jsonify(dict(session))

@app.route('/debug/headers')
def debug_headers():
    return jsonify(dict(request.headers))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5020)