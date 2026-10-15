import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.utils import secure_filename
import torch
import torch.nn as nn
import torch.nn.functional as F
from torchvision import models, transforms
from PIL import Image
import mysql.connector
from datetime import datetime
import hashlib
import cv2
import numpy as np
import json
import uuid
import pickle
from torch_geometric.data import Data
from torch_geometric.nn import GATConv, global_mean_pool
from skimage.segmentation import slic


# ===== Flask Setup =====
app = Flask(__name__)
app.secret_key = 'sforensic'
UPLOAD_FOLDER    = "static/uploads"
PROCESSED_FOLDER = "static/processed"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER']    = UPLOAD_FOLDER
app.config['PROCESSED_FOLDER'] = PROCESSED_FOLDER


# ===== Database Configuration =====
DB_CONFIG = {
    'host':     'localhost',
    'user':     'root',
    'password': 'root',
    'database': 'forensic_db'
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


# ===== ADMIN CREDENTIALS =====
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin'


# ===== BLOCKCHAIN CLASSES =====
class Block:
    def __init__(self, index, timestamp, data, previous_hash, nonce=0):
        self.index         = index
        self.timestamp     = timestamp
        self.data          = data
        self.previous_hash = previous_hash
        self.nonce         = nonce
        self.hash          = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index":         self.index,
            "timestamp":     str(self.timestamp),
            "data":          self.data,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty=4):
        target = '0' * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash   = self.calculate_hash()
        return self.hash


class ForensicBlockchain:
    def __init__(self):
        self.chain                = []
        self.difficulty           = 4
        self.pending_transactions = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, datetime.now(), {
            "type":    "genesis",
            "message": "ForensicAI Blockchain Initialized"
        }, "0")
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)

    def get_latest_block(self):
        return self.chain[-1]

    def add_forensic_record(self, user_id, filename, processed_filename, prediction, confidence):
        record_data = {
            "record_id":          str(uuid.uuid4()),
            "type":               "forensic_analysis",
            "user_id":            user_id,
            "filename":           filename,
            "processed_filename": processed_filename,
            "prediction":         prediction,
            "confidence":         float(confidence),
            "timestamp":          datetime.now().isoformat(),
            "data_hash":          self._hash_forensic_data(filename, prediction, confidence)
        }
        new_block = Block(
            index         = len(self.chain),
            timestamp     = datetime.now(),
            data          = record_data,
            previous_hash = self.get_latest_block().hash
        )
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        return new_block.hash, record_data['record_id']

    def _hash_forensic_data(self, filename, prediction, confidence):
        data_string = f"{filename}{prediction}{confidence}"
        return hashlib.sha256(data_string.encode()).hexdigest()

    def verify_chain(self):
        for i in range(1, len(self.chain)):
            current_block  = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.hash != current_block.calculate_hash():
                return False, f"Block {i} has been tampered with (hash mismatch)"
            if current_block.previous_hash != previous_block.hash:
                return False, f"Block {i} chain linkage broken (previous hash mismatch)"
        return True, "Blockchain is valid and secure"

    def get_user_records(self, user_id):
        records = []
        for block in self.chain[1:]:
            if block.data.get('type') == 'forensic_analysis' and block.data.get('user_id') == user_id:
                records.append({
                    'block_index': block.index,
                    'block_hash':  block.hash,
                    'timestamp':   block.timestamp,
                    'record_id':   block.data.get('record_id'),
                    'prediction':  block.data.get('prediction'),
                    'confidence':  block.data.get('confidence'),
                    'data_hash':   block.data.get('data_hash'),
                    'filename':    block.data.get('filename')
                })
        return records

    def verify_record_integrity(self, record_id):
        for block in self.chain:
            if block.data.get('record_id') == record_id:
                if block.hash != block.calculate_hash():
                    return False, "Record has been tampered with (block hash modified)"
                data_hash = self._hash_forensic_data(
                    block.data['filename'],
                    block.data['prediction'],
                    block.data['confidence']
                )
                if data_hash != block.data['data_hash']:
                    return False, "Forensic data has been modified"
                return True, "Record is authentic and unmodified"
        return False, "Record not found in blockchain"

    def get_chain_statistics(self):
        return {
            'total_blocks':      len(self.chain),
            'total_records':     len(self.chain) - 1,
            'chain_valid':       self.verify_chain()[0],
            'difficulty':        self.difficulty,
            'latest_block_hash': self.get_latest_block().hash
        }


# ===== Initialize Blockchain =====
BLOCKCHAIN_FILE = 'forensic_blockchain.pkl'

def load_blockchain():
    if os.path.exists(BLOCKCHAIN_FILE):
        try:
            with open(BLOCKCHAIN_FILE, 'rb') as f:
                blockchain = pickle.load(f)
                is_valid, message = blockchain.verify_chain()
                if not is_valid:
                    print("[WARN] Blockchain loaded but validation failed!")
                    print(f"   Reason: {message}")
                return blockchain
        except:
            print("[WARN] Error loading blockchain file, creating new one")
            return ForensicBlockchain()
    return ForensicBlockchain()

def save_blockchain(blockchain):
    with open(BLOCKCHAIN_FILE, 'wb') as f:
        pickle.dump(blockchain, f)

forensic_blockchain = load_blockchain()


# ===== Initialize Database =====
def init_db():
    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            username   VARCHAR(50)  UNIQUE NOT NULL,
            email      VARCHAR(100) UNIQUE NOT NULL,
            password   VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id                 INT AUTO_INCREMENT PRIMARY KEY,
            user_id            INT,
            filename           VARCHAR(255) NOT NULL,
            processed_filename VARCHAR(255),
            prediction         VARCHAR(100) NOT NULL,
            confidence         DECIMAL(5,2) NOT NULL,
            block_hash         VARCHAR(64),
            record_id          VARCHAR(36),
            report             TEXT,
            created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()
    print("[OK] Database initialized - existing data preserved")


# ===== Labels =====
CLASS_LABELS = [
    "Automatic rifle",
    "Invalid input",
    "Knife Wound",
    "No wound found",
    "Revolver Wound",
    "Screwdriver Wound",
    "Shotgun Wound"
]


# ===== Model Configuration (must match train.ipynb exactly) =====
IMG_SIZE        = 224
NUM_SUPERPIXELS = 75
K_NEIGHBORS     = 5


# ===== CNN Feature Extractor =====
class CNNFeatureExtractor(nn.Module):
    def __init__(self):
        super().__init__()
        weights       = models.EfficientNet_B0_Weights.DEFAULT
        backbone      = models.efficientnet_b0(weights=weights)
        self.features = backbone.features
        for param in self.features.parameters():
            param.requires_grad = False

    def forward(self, x):
        x = self.features(x)
        x = F.adaptive_avg_pool2d(x, 1)
        x = x.flatten(1)
        return x


# ===== Hybrid CNN + GNN Model (exact match to train.ipynb) =====
class HybridCNNGNN(nn.Module):
    def __init__(self, num_classes):
        super().__init__()

        # CNN branch
        self.cnn    = CNNFeatureExtractor()
        self.cnn_fc = nn.Sequential(
            nn.Linear(1280, 256),
            nn.ReLU(),
            nn.Dropout(0.3)
        )

        # GNN branch
        self.gat1 = GATConv(3,   64,  heads=4, concat=True)   # 3 -> 256
        self.gat2 = GATConv(256, 128, heads=1, concat=True)    # 256 -> 128

        # Fusion classifier: 256 (CNN) + 128 (GNN) = 384
        self.classifier = nn.Sequential(
            nn.Linear(384, 256),
            nn.ReLU(),
            nn.Dropout(0.4),
            nn.Linear(256, num_classes)
        )

    def forward(self, data):
        images = data.image
        if images.dim() == 3:
            images = images.unsqueeze(0)
        images = images.to(device)

        # CNN branch
        cnn_features = self.cnn(images)
        cnn_features = self.cnn_fc(cnn_features)

        # GNN branch
        x          = data.x.to(device)
        edge_index = data.edge_index.to(device)

        if not hasattr(data, 'batch') or data.batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=device)
        else:
            batch = data.batch.to(device)

        x = F.relu(self.gat1(x, edge_index))
        x = F.relu(self.gat2(x, edge_index))
        gnn_features = global_mean_pool(x, batch)

        fused  = torch.cat([cnn_features, gnn_features], dim=1)
        logits = self.classifier(fused)
        return logits


# ===== Graph Builder =====
def build_graph(image_bgr):
    image_rgb = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2RGB)
    image_rgb = cv2.resize(image_rgb, (IMG_SIZE, IMG_SIZE))
    segments  = slic(image_rgb, n_segments=NUM_SUPERPIXELS, compactness=10, start_label=0)
    num_nodes = segments.max() + 1

    node_features = []
    centers       = []

    for i in range(num_nodes):
        mask   = segments == i
        pixels = image_rgb[mask]
        if len(pixels) == 0:
            mean_rgb = np.array([0, 0, 0], dtype=np.float32)
            center   = (0.0, 0.0)
        else:
            mean_rgb = pixels.mean(axis=0) / 255.0
            coords   = np.argwhere(mask)
            cy, cx   = coords.mean(axis=0)
            center   = (cx, cy)
        node_features.append(mean_rgb.astype(np.float32))
        centers.append(center)

    node_features = np.array(node_features, dtype=np.float32)
    edges         = []

    for i in range(num_nodes):
        xi, yi    = centers[i]
        distances = []
        for j in range(num_nodes):
            if i == j:
                continue
            xj, yj = centers[j]
            d      = (xi - xj) ** 2 + (yi - yj) ** 2
            distances.append((d, j))
        distances.sort(key=lambda x: x[0])
        for _, j in distances[:K_NEIGHBORS]:
            edges.append([i, j])

    if len(edges) == 0:
        edges = [[0, 0]]

    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    x          = torch.tensor(node_features, dtype=torch.float)
    return x, edge_index


# ===== Transform (must match train.ipynb normalization) =====
transform = transforms.Compose([
    transforms.Resize((IMG_SIZE, IMG_SIZE)),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406],
                         std=[0.229, 0.224, 0.225])
])


# ===== Load Model =====
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model  = HybridCNNGNN(num_classes=len(CLASS_LABELS)).to(device)

try:
    checkpoint = torch.load(
        "best_cnn_gnn_model.pth",
        map_location=device,
        weights_only=False
    )
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    print("[OK] Model loaded successfully")
except FileNotFoundError:
    print("[WARN] best_cnn_gnn_model.pth not found - place model file in project root")


# ===== Helper Functions =====
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hashlib.sha256(password.encode()).hexdigest() == hashed

def is_valid_image(filepath):
    try:
        img           = Image.open(filepath)
        width, height = img.size
        if width < 100 or height < 100:
            return False
        if os.path.getsize(filepath) < 1024:
            return False
        return True
    except Exception:
        return False

def preprocess_forensic_image(image_path, output_path):
    try:
        img = cv2.imread(image_path)
        if img is None:
            return False

        lab             = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
        l, a, b         = cv2.split(lab)
        clahe           = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
        l_enhanced      = clahe.apply(l)
        lab_enhanced    = cv2.merge((l_enhanced, a, b))
        enhanced        = cv2.cvtColor(lab_enhanced, cv2.COLOR_LAB2BGR)

        blurred         = cv2.GaussianBlur(enhanced, (5, 5), 0)
        gaussian        = cv2.GaussianBlur(blurred, (9, 9), 10.0)
        unsharp         = cv2.addWeighted(blurred, 1.5, gaussian, -0.5, 0)

        gamma           = 1.1
        gamma_corrected = np.array(255 * (unsharp / 255) ** gamma, dtype='uint8')

        kernel          = np.array([[-1,-1,-1], [-1,9,-1], [-1,-1,-1]])
        sharpened       = cv2.filter2D(gamma_corrected, -1, kernel)

        cv2.imwrite(output_path, sharpened)
        return True
    except Exception as e:
        print(f"Preprocessing error: {e}")
        return False


# ===== LLM Forensic Report Generator =====
def generate_report(prediction, confidence):
    API_KEY = os.getenv("OPENROUTER_API_KEY", "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")

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "HTTP-Referer":  "http://localhost",
        "X-Title":       "ForensicAI"
    }

    wound_context = {
        "Automatic rifle": (
            "High-velocity projectile wound pattern typically associated with automatic rifle discharge. "
            "Characterized by entrance wound with stippling, extensive internal cavitation, "
            "and potentially fragmented exit wound."
        ),
        "Knife Wound": (
            "Sharp force injury consistent with knife stabbing or slashing. "
            "Characterized by clean incised margins, absence of bridging tissue, "
            "and linear or crescent-shaped wound outline."
        ),
        "Revolver Wound": (
            "Gunshot wound pattern consistent with revolver caliber projectile. "
            "Typically presents circular to oval entrance wound with marginal abrasion ring."
        ),
        "Screwdriver Wound": (
            "Puncture wound consistent with screwdriver-type implement. "
            "Presents as a narrow, deep puncture with stellate or cruciform laceration pattern."
        ),
        "Shotgun Wound": (
            "Multiple pellet entry wounds or a single large-caliber wound consistent with shotgun discharge. "
            "Contact range presents rat-hole or stellate pattern; distance increases pellet dispersal."
        ),
        "No wound found": (
            "No identifiable wound pattern detected in the submitted image."
        ),
    }

    if prediction == "Invalid input":
        prompt = f"""
        A forensic wound image was submitted to the ForensicAI classification system.
        The system classified this image as INVALID INPUT with a confidence of {confidence:.2f}%.
        Write a concise formal forensic report in a single paragraph without bullet points or headings. Include:
        - What an Invalid input classification means in forensic image analysis
        - Likely reasons the image was rejected (poor quality, non-forensic content, insufficient resolution)
        - Risk of attempting weapon classification on an invalid image
        - Clear recommendation to resubmit a proper forensic photograph
        - Note that no weapon identification or wound classification can be made from this image
        Keep the language formal, forensically accurate, and professional.
        """
        system_prompt = (
            "You are an expert forensic pathologist specializing in wound pattern analysis and weapon identification. "
            "Generate concise, formal forensic reports based on AI-assisted wound classification."
        )
    elif prediction == "No wound found":
        prompt = f"""
        A forensic image was analyzed by the ForensicAI CNN-GNN ensemble model.
        The system classified the image as: No wound found, with a confidence score of {confidence:.2f}%.
        Write a concise formal forensic report in a single paragraph without bullet points or headings. Include:
        - What a No wound found result means forensically
        - Whether this rules out injury entirely or only absence of visible surface wounds
        - Recommendation for further examination such as internal post-mortem or imaging
        - Documentation note for chain of evidence purposes
        Keep the language formal, clinically precise, and evidence-based.
        """
        system_prompt = (
            "You are an expert forensic pathologist specializing in wound pattern analysis. "
            "Generate concise, formal forensic reports based on AI-assisted classification."
        )
    else:
        context = wound_context.get(prediction, prediction)
        low_confidence_note = (
            " Note that the model confidence is below 70%, indicating borderline wound features. "
            "This result should be treated as preliminary and requires expert forensic review before evidentiary use."
            if confidence < 70 else ""
        )
        prompt = f"""
        A forensic wound image was analyzed by the ForensicAI system using a CNN-GNN Ensemble Learning model.
        The system classified the wound as: {prediction} ({context}),
        with a confidence score of {confidence:.2f}%.{low_confidence_note}
        Write a concise formal forensic pathology report in a single paragraph without bullet points or headings. Include:
        - The weapon type or wound class identified and its forensic significance
        - Key morphological wound characteristics expected for this classification
        - Forensic implications about the weapon used and mechanism of injury
        - Whether this finding requires immediate escalation to law enforcement or senior forensic examiner
        - Recommended next steps for the investigating forensic officer or pathologist
        Keep the language formal, forensically precise, and evidence-based.
        """
        system_prompt = (
            "You are an expert forensic pathologist specializing in wound pattern analysis and weapon identification. "
            "Generate concise, formal forensic pathology reports based on AI-assisted wound classification from images."
        )

    data = {
        "model": "meta-llama/llama-3.1-8b-instruct",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": prompt.strip()}
        ],
        "temperature": 0.6,
        "max_tokens":  500
    }

    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=30
        )
        if response.status_code == 200:
            return response.json()['choices'][0]['message']['content'].strip()
        else:
            return f"Report generation failed: {response.status_code} - {response.text}"
    except requests.exceptions.Timeout:
        return "Report generation timed out. Please try again."
    except Exception as e:
        return f"Error during report generation: {str(e)}"


# ===================================================
# ===== ROUTES =====
# ===================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email    = request.form['email']
        password = request.form['password']

        conn   = get_db_connection()
        cursor = conn.cursor()
        try:
            hashed_password = hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password)
            )
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error:
            flash('Username or email already exists!', 'error')
        finally:
            conn.close()

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn   = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and verify_password(password, user[1]):
            session['user_id']  = user[0]
            session['username'] = username
            return redirect(url_for('upload'))
        else:
            flash('Invalid username or password!', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected!', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected!', 'error')
            return redirect(request.url)

        if file:
            filename  = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_")
            filename  = timestamp + filename
            filepath  = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            if not is_valid_image(filepath):
                os.remove(filepath)
                flash('Invalid image file. Please upload a valid forensic image.', 'error')
                return redirect(request.url)

            processed_filename    = "processed_" + filename
            processed_filepath    = os.path.join(app.config['PROCESSED_FOLDER'], processed_filename)
            preprocessing_success = preprocess_forensic_image(filepath, processed_filepath)
            if not preprocessing_success:
                processed_filename = None

            try:
                # Read image for both CNN and GNN branches
                img_bgr    = cv2.imread(filepath)
                img_rgb    = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
                img_pil    = Image.fromarray(img_rgb)
                cnn_tensor = transform(img_pil)

                # Build superpixel graph
                x, edge_index = build_graph(img_bgr)

                # Create PyG Data object
                data       = Data(x=x, edge_index=edge_index)
                data.image = cnn_tensor

                with torch.no_grad():
                    outputs         = model(data)
                    probs           = torch.nn.functional.softmax(outputs, dim=1)
                    predicted_class = torch.argmax(probs, 1).item()
                    confidence      = probs[0][predicted_class].item() * 100

                predicted_label = CLASS_LABELS[predicted_class]
                report          = generate_report(predicted_label, confidence)

                block_hash, record_id = forensic_blockchain.add_forensic_record(
                    user_id            = session['user_id'],
                    filename           = filename,
                    processed_filename = processed_filename,
                    prediction         = predicted_label,
                    confidence         = confidence
                )
                save_blockchain(forensic_blockchain)

                conn   = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO predictions
                    (user_id, filename, processed_filename, prediction, confidence, block_hash, record_id, report)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (session['user_id'], filename, processed_filename,
                      predicted_label, confidence, block_hash, record_id, report))
                conn.commit()
                conn.close()

                if predicted_label == "Invalid input":
                    flash('The uploaded image appears to be invalid or not suitable for forensic wound analysis.', 'warning')

                return render_template('result.html',
                                       filename           = filename,
                                       processed_filename = processed_filename,
                                       label              = predicted_label,
                                       confidence         = round(confidence, 2),
                                       block_hash         = block_hash,
                                       report             = report)

            except Exception as e:
                print(f"Processing error: {e}")
                if os.path.exists(filepath):
                    os.remove(filepath)
                if processed_filename and os.path.exists(processed_filepath):
                    os.remove(processed_filepath)
                flash('Error processing image. Please try again with a different image.', 'error')
                return redirect(request.url)

    return render_template('upload.html')


@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT filename, processed_filename, prediction, confidence,
               created_at, block_hash, record_id, report
        FROM predictions
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (session['user_id'],))

    raw_predictions = cursor.fetchall()
    predictions = [
        {
            'filename':           row[0],
            'processed_filename': row[1],
            'prediction':         row[2],
            'confidence':         float(row[3]),
            'created_at':         row[4],
            'block_hash':         row[5],
            'record_id':          row[6],
            'report':             row[7]
        }
        for row in raw_predictions
    ]
    conn.close()

    return render_template('history.html', predictions=predictions)


@app.route('/analysis')
def analysis():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('analysis.html')


# ===== BLOCKCHAIN ROUTES =====
@app.route('/blockchain')
def blockchain_view():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    is_valid, message = forensic_blockchain.verify_chain()
    user_records      = forensic_blockchain.get_user_records(session['user_id'])
    stats             = forensic_blockchain.get_chain_statistics()

    return render_template('blockchain.html',
                           records  = user_records,
                           is_valid = is_valid,
                           message  = message,
                           stats    = stats)


@app.route('/verify_record/<record_id>')
def verify_record(record_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    is_valid, message = forensic_blockchain.verify_record_integrity(record_id)
    return jsonify({
        'valid':     is_valid,
        'message':   message,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/blockchain/verify')
def verify_blockchain():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    is_valid, message = forensic_blockchain.verify_chain()
    return jsonify({
        'valid':        is_valid,
        'message':      message,
        'total_blocks': len(forensic_blockchain.chain),
        'verified_at':  datetime.now().isoformat()
    })


# ===================================================
# ===== ADMIN ROUTES =====
# ===================================================

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = 'Invalid admin credentials.'
    return render_template('admin_login.html', error=error)


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))


@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, email, created_at FROM users ORDER BY id DESC")
    raw_users = cursor.fetchall()
    users = [
        {
            'id':         row[0],
            'username':   row[1],
            'email':      row[2],
            'created_at': row[3]
        }
        for row in raw_users
    ]

    cursor.execute("""
        SELECT p.id, p.filename, p.prediction, p.confidence,
               p.created_at, p.block_hash, u.username
        FROM predictions p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    """)
    raw_preds = cursor.fetchall()
    predictions = [
        {
            'id':         row[0],
            'filename':   row[1],
            'prediction': row[2],
            'confidence': float(row[3]),
            'created_at': row[4],
            'block_hash': row[5],
            'username':   row[6]
        }
        for row in raw_preds
    ]
    conn.close()

    class_counts = {}
    for p in predictions:
        c = p['prediction']
        class_counts[c] = class_counts.get(c, 0) + 1

    total_users = len(users)
    total_scans = len(predictions)

    return render_template('admin_dashboard.html',
                           users        = users,
                           predictions  = predictions,
                           total_users  = total_users,
                           total_scans  = total_scans,
                           grade_counts = class_counts)

# Add this after app = Flask(__name__)
@app.template_filter('get_class_color')
def get_class_color(label):
    colors = {
        "Automatic rifle":   "class-color-rifle",
        "Invalid input":     "class-color-invalid",
        "Knife Wound":       "class-color-knife",
        "No wound found":    "class-color-nowound",
        "Revolver Wound":    "class-color-revolver",
        "Screwdriver Wound": "class-color-screw",
        "Shotgun Wound":     "class-color-shotgun",
    }
    return colors.get(label, "class-color-invalid")
# ===================================================

if __name__ == "__main__":
    init_db()
    print("\n" + "="*70)
    print("  ForensicAI - Blockchain-Secured Weapon & Wound Analysis System")
    print("="*70)
    print("Blockchain Status:")
    print(f"   File    : {'Loaded' if os.path.exists(BLOCKCHAIN_FILE) else 'New'}")
    print(f"   Blocks  : {len(forensic_blockchain.chain)}")
    print(f"   Records : {len(forensic_blockchain.chain) - 1}")

    is_valid, msg = forensic_blockchain.verify_chain()
    print(f"   Status  : {'VALID' if is_valid else 'INVALID'}")
    if not is_valid:
        print(f"   Issue   : {msg}")

    print("="*70)
    print("Security : Automatic tampering detection enabled")
    print("LLM      : OpenRouter LLaMA-3 8B integrated")
    print("Admin    : http://127.0.0.1:5000/admin")
    print("="*70 + "\n")

    app.run(debug=True)