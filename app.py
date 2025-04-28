from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
import os
import uuid
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
app.secret_key = 'sua_chave_secreta'

# Inicializa o banco de dados
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Cria a tabela users se não existir
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            photo TEXT
        )
    ''')

    # Cria a tabela messages se não existir
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Verifica se a coluna photo existe (caso a tabela já existisse antes sem a coluna)
    c.execute("PRAGMA table_info(users)")
    colunas = [col[1] for col in c.fetchall()]
    if 'photo' not in colunas:
        c.execute('ALTER TABLE users ADD COLUMN photo TEXT')

    conn.commit()
    conn.close()

init_db()


# Rota de login
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            session['user'] = username
            return redirect('/home')
        else:
            return 'Usuário ou senha inválidos', 401

    return render_template('login.html')

# Página inicial (Lista de conversas)
@app.route('/home')
def home():
    if 'user' not in session:
        return redirect('/')
    return render_template('home.html', username=session['user'])

# Página de chat
@app.route('/chat/<contato>')
def chat(contato):
    if 'user' not in session:
        return redirect('/')
    return render_template('chat.html', username=session['user'], contato=contato)

# API - Enviar mensagem
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user' not in session:
        return 'Unauthorized', 401

    receiver = request.form.get('receiver', '')  # agora vai pegar o destinatário
    message = request.form['message']
    sender = session['user']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)', (sender, receiver, message))
    conn.commit()
    conn.close()

    return 'OK'

# API - Buscar mensagens com um contato específico
@app.route('/get_messages/<contato>')
def get_messages(contato):
    if 'user' not in session:
        return 'Unauthorized', 401

    user = session['user']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        SELECT sender, message, timestamp FROM messages
        WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
        ORDER BY timestamp ASC
    ''', (user, contato, contato, user))
    messages = c.fetchall()
    conn.close()

    return jsonify(messages)

# API - Listar conversas (últimas mensagens por contato)
@app.route('/get_conversations')
def get_conversations():
    if 'user' not in session:
        return 'Unauthorized', 401

    user = session['user']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        SELECT 
            CASE
                WHEN sender = ? THEN receiver
                ELSE sender
            END as contato,
            message,
            timestamp
        FROM messages
        WHERE sender = ? OR receiver = ?
        ORDER BY timestamp DESC
    ''', (user, user, user))

    raw = c.fetchall()

    conversas = {}
    for contato, mensagem, horario in raw:
        if contato not in conversas:
            # Aqui buscar a foto também:
            c.execute('SELECT photo FROM users WHERE username = ?', (contato,))
            user_info = c.fetchone()
            photo = user_info[0] if user_info and user_info[0] else 'default.png'

            conversas[contato] = {
                'contato': contato,
                'ultima_mensagem': mensagem,
                'horario': horario,
                'photo': photo
            }

    conn.close()

    return jsonify(list(conversas.values()))



# Verificar se um usuário existe
@app.route('/verificar_usuario/<username>')
def verificar_usuario(username):
    if 'user' not in session:
        return 'Unauthorized', 401

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    if user:
        return 'Usuário encontrado', 200
    else:
        return 'Usuário não encontrado', 404



# Adicione dentro do app.py
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return 'Usuário já existe!', 400
    conn.close()

    return 'Usuário cadastrado com sucesso!'


# Rota de logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')



###################################

# Buscar foto de perfil de um contato
@app.route('/foto_usuario/<username>')
def foto_usuario(username):
    if 'user' not in session:
        return 'Unauthorized', 401

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT photo FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    if user:
        return jsonify({'photo': user[0]})
    else:
        return jsonify({'photo': None})


# Listar todos os usuários (exceto o usuário logado)
@app.route('/listar_usuarios')
def listar_usuarios():
    if 'user' not in session:
        return 'Unauthorized', 401

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE username != ?', (session['user'],))
    users = [row[0] for row in c.fetchall()]
    conn.close()

    return jsonify(users)

@app.route('/upload_photo', methods=['POST'])
def upload_photo():
    if 'user' not in session:
        return 'Unauthorized', 401

    photo = request.files.get('photo')
    if not photo:
        return 'Nenhuma foto enviada', 400

    filename = secure_filename(photo.filename)
    ext = filename.rsplit('.', 1)[1].lower()
    photo_filename = f"{uuid.uuid4()}.{ext}"

    upload_path = os.path.join('static', 'uploads', photo_filename)
    os.makedirs(os.path.dirname(upload_path), exist_ok=True)
    photo.save(upload_path)

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('UPDATE users SET photo = ? WHERE username = ?', (photo_filename, session['user']))
    conn.commit()
    conn.close()

    return 'Foto atualizada com sucesso!', 200


###################################

if __name__ == '__main__':
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
