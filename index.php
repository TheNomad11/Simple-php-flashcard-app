<?php
// Session security configuration (BEFORE session_start)
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);        // Requires HTTPS
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_lifetime', 0);      // Session cookie

session_start();

// Security Headers
header("X-Frame-Options: SAMEORIGIN");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// Content Security Policy
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self';");

// Security: Regenerate session ID periodically
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}

// Session timeout (30 minutes)
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 1800)) {
    session_unset();
    session_destroy();
    header('Location: index.php');
    exit;
}
$_SESSION['last_activity'] = time();

// Configuration
define('DATA_DIR', __DIR__ . '/data');
define('DECKS_DIR', DATA_DIR . '/decks');
define('USERS_FILE', DATA_DIR . '/users.txt');
define('MEDIA_DIR', DATA_DIR . '/media');
define('PROGRESS_DIR', DATA_DIR . '/progress');

// Security: Allowed file extensions
define('ALLOWED_IMAGE_TYPES', ['jpg', 'jpeg', 'png', 'gif', 'webp']);
define('ALLOWED_AUDIO_TYPES', ['mp3', 'wav', 'ogg', 'm4a']);
define('MAX_FILE_SIZE', 5242880); // 5MB

// Registration Settings
define('ALLOW_REGISTRATION', false);  // Set to false to disable public registration

// Read-Only Mode Settings
define('READ_ONLY_MODE', true);     // Set to true for public viewing (no editing)
define('REQUIRE_LOGIN_TO_VIEW', false); // Set to false to allow viewing without login

// Initialize directories
function initDirectories() {
    $dirs = [DATA_DIR, DECKS_DIR, MEDIA_DIR, PROGRESS_DIR];
    foreach ($dirs as $dir) {
        if (!file_exists($dir)) {
            mkdir($dir, 0755, true);
            chmod($dir, 0755);
        }
    }
    if (!file_exists(USERS_FILE)) {
        file_put_contents(USERS_FILE, '');
        chmod(USERS_FILE, 0644);
    }
    
    // Create .htaccess to protect data directory
    $htaccess = DATA_DIR . '/.htaccess';
    if (!file_exists($htaccess)) {
        file_put_contents($htaccess, "Require all denied\n");
        chmod($htaccess, 0644);
    }
}

initDirectories();

// CSRF Protection
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Rate Limiting (simple implementation)
function checkRateLimit($action, $maxAttempts = 5, $timeWindow = 300) {
    $key = 'rate_limit_' . $action . '_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['count' => 0, 'start' => time()];
    }
    
    $rateData = $_SESSION[$key];
    
    // Reset if time window passed
    if (time() - $rateData['start'] > $timeWindow) {
        $_SESSION[$key] = ['count' => 1, 'start' => time()];
        return true;
    }
    
    // Check limit
    if ($rateData['count'] >= $maxAttempts) {
        return false;
    }
    
    $_SESSION[$key]['count']++;
    return true;
}

// Input Sanitization
function sanitizeInput($input, $maxLength = 500) {
    $input = trim($input);
    $input = substr($input, 0, $maxLength);
    return $input;
}

function validateDeckId($deckId) {
    // Only alphanumeric, underscore, hyphen
    if (!preg_match('/^[a-zA-Z0-9_-]{1,100}$/', $deckId)) {
        return false;
    }
    return true;
}

function validateCardId($cardId) {
    // Validate format (uniqid format or similar)
    if (!preg_match('/^[a-f0-9]{13,23}$/', $cardId)) {
        return false;
    }
    return true;
}

// Authentication Functions
function registerUser($username, $password) {
    $username = sanitizeInput($username, 50);
    
    // Stronger validation
    if (strlen($username) < 3 || strlen($username) > 50) {
        return false;
    }
    if (strlen($password) < 8) {
        return false;
    }
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
        return false;
    }
    
    $users = file_exists(USERS_FILE) ? file(USERS_FILE, FILE_IGNORE_NEW_LINES) : [];
    foreach ($users as $user) {
        if (empty($user)) continue;
        list($u, $p) = explode(':', $user, 2);
        if ($u === $username) {
            return false;
        }
    }
    
    $hash = password_hash($password, PASSWORD_DEFAULT);
    file_put_contents(USERS_FILE, "$username:$hash\n", FILE_APPEND | LOCK_EX);
    return true;
}

function loginUser($username, $password) {
    if (!file_exists(USERS_FILE)) return false;
    
    $username = sanitizeInput($username, 50);
    
    $users = file(USERS_FILE, FILE_IGNORE_NEW_LINES);
    foreach ($users as $user) {
        if (empty($user)) continue;
        list($u, $h) = explode(':', $user, 2);
        if ($u === $username && password_verify($password, $h)) {
            // Security: Regenerate session ID on login
            session_regenerate_id(true);
            $_SESSION['user'] = $username;
            $_SESSION['login_time'] = time();
            return true;
        }
    }
    return false;
}

function isLoggedIn() {
    return isset($_SESSION['user']);
}

function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: index.php');
        exit;
    }
}

function logout() {
    session_unset();
    session_destroy();
}

// Progress Tracking Functions
function getProgressFile($deckId) {
    if (!validateDeckId($deckId)) {
        die('Invalid deck ID');
    }
    $username = $_SESSION['user'];
    $safeUsername = preg_replace('/[^a-zA-Z0-9_-]/', '_', $username);
    return PROGRESS_DIR . '/' . $safeUsername . '_' . $deckId . '.txt';
}

function getProgress($deckId) {
    $file = getProgressFile($deckId);
    if (!file_exists($file)) {
        return ['known' => [], 'unknown' => []];
    }
    
    $content = file_get_contents($file);
    $lines = explode("\n", trim($content));
    
    $progress = ['known' => [], 'unknown' => []];
    foreach ($lines as $line) {
        if (empty($line)) continue;
        $parts = explode('|', $line);
        if (count($parts) !== 2) continue;
        
        $cardId = $parts[0];
        $status = $parts[1];
        
        if (!validateCardId($cardId)) continue;
        
        if ($status === 'known') {
            $progress['known'][] = $cardId;
        } elseif ($status === 'unknown') {
            $progress['unknown'][] = $cardId;
        }
    }
    
    return $progress;
}

function saveProgress($deckId, $cardId, $status) {
    if (!validateDeckId($deckId) || !validateCardId($cardId)) {
        return false;
    }
    if (!in_array($status, ['known', 'unknown'])) {
        return false;
    }
    
    $file = getProgressFile($deckId);
    $progress = getProgress($deckId);
    
    // Remove from both arrays
    $progress['known'] = array_diff($progress['known'], [$cardId]);
    $progress['unknown'] = array_diff($progress['unknown'], [$cardId]);
    
    // Add to appropriate array
    if ($status === 'known') {
        $progress['known'][] = $cardId;
    } elseif ($status === 'unknown') {
        $progress['unknown'][] = $cardId;
    }
    
    // Write to file with lock
    $lines = [];
    foreach ($progress['known'] as $id) {
        $lines[] = "$id|known";
    }
    foreach ($progress['unknown'] as $id) {
        $lines[] = "$id|unknown";
    }
    
    file_put_contents($file, implode("\n", $lines), LOCK_EX);
    chmod($file, 0644);
    return true;
}

function resetProgress($deckId) {
    if (!validateDeckId($deckId)) {
        return false;
    }
    $file = getProgressFile($deckId);
    if (file_exists($file)) {
        unlink($file);
    }
    return true;
}

function getDeckStats($deckId) {
    $cards = getCards($deckId);
    $progress = getProgress($deckId);
    
    $total = count($cards);
    $known = count($progress['known']);
    $unknown = count($progress['unknown']);
    $notReviewed = $total - $known - $unknown;
    
    return [
        'total' => $total,
        'known' => $known,
        'unknown' => $unknown,
        'notReviewed' => $notReviewed
    ];
}

// Deck Functions
function getDeckPath($deckId) {
    if (!validateDeckId($deckId)) {
        die('Invalid deck ID');
    }
    return DECKS_DIR . '/' . $deckId . '.txt';
}

function getDecks() {
    $decks = [];
    if (!is_dir(DECKS_DIR)) return $decks;
    
    foreach (glob(DECKS_DIR . '/*.txt') as $file) {
        $deckId = basename($file, '.txt');
        if (!validateDeckId($deckId)) continue;
        
        $content = file_get_contents($file);
        $lines = explode("\n", $content);
        $deckName = isset($lines[0]) ? sanitizeInput($lines[0], 200) : $deckId;
        $stats = getDeckStats($deckId);
        $decks[$deckId] = [
            'name' => $deckName, 
            'id' => $deckId,
            'stats' => $stats
        ];
    }
    return $decks;
}

function createDeck($name) {
    $name = sanitizeInput($name, 200);
    if (empty($name)) return false;
    
    $deckId = preg_replace('/[^a-z0-9_-]/', '_', strtolower($name)) . '_' . bin2hex(random_bytes(4));
    $path = getDeckPath($deckId);
    file_put_contents($path, $name . "\n", LOCK_EX);
    chmod($path, 0644);
    return $deckId;
}

function updateDeck($deckId, $name) {
    if (!validateDeckId($deckId)) return false;
    $name = sanitizeInput($name, 200);
    if (empty($name)) return false;
    
    $path = getDeckPath($deckId);
    if (!file_exists($path)) return false;
    
    $content = file_get_contents($path);
    $lines = explode("\n", $content);
    $lines[0] = $name;
    file_put_contents($path, implode("\n", $lines), LOCK_EX);
    return true;
}

function deleteDeck($deckId) {
    if (!validateDeckId($deckId)) return false;
    
    $path = getDeckPath($deckId);
    if (file_exists($path)) {
        // Delete all media files first
        $cards = getCards($deckId);
        foreach ($cards as $card) {
            if (!empty($card['image'])) deleteMedia($card['image']);
            if (!empty($card['audio'])) deleteMedia($card['audio']);
        }
        
        unlink($path);
        
        // Also delete progress file
        $progressFile = getProgressFile($deckId);
        if (file_exists($progressFile)) {
            unlink($progressFile);
        }
        return true;
    }
    return false;
}

// Card Functions
function getCards($deckId) {
    if (!validateDeckId($deckId)) return [];
    
    $path = getDeckPath($deckId);
    if (!file_exists($path)) return [];
    
    $content = file_get_contents($path);
    $lines = explode("\n", $content);
    array_shift($lines); // Remove deck name
    
    $cards = [];
    foreach ($lines as $line) {
        if (trim($line) === '') continue;
        $parts = explode('|', $line);
        if (count($parts) >= 4) {
            $cardId = $parts[0];
            if (!validateCardId($cardId)) continue;
            
            $cards[] = [
                'id' => $cardId,
                'front' => sanitizeInput($parts[1], 500),
                'back' => sanitizeInput($parts[2], 500),
                'image' => isset($parts[3]) ? basename($parts[3]) : '',
                'audio' => isset($parts[4]) ? basename($parts[4]) : ''
            ];
        }
    }
    return $cards;
}

function addCard($deckId, $front, $back, $image = '', $audio = '') {
    if (!validateDeckId($deckId)) return false;
    
    $front = sanitizeInput($front, 500);
    $back = sanitizeInput($back, 500);
    if (empty($front) || empty($back)) return false;
    
    $path = getDeckPath($deckId);
    if (!file_exists($path)) return false;
    
    $cardId = bin2hex(random_bytes(8));
    $image = basename($image);
    $audio = basename($audio);
    $line = "$cardId|$front|$back|$image|$audio\n";
    file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
    return $cardId;
}

function updateCard($deckId, $cardId, $front, $back, $image = '', $audio = '') {
    if (!validateDeckId($deckId) || !validateCardId($cardId)) return false;
    
    $front = sanitizeInput($front, 500);
    $back = sanitizeInput($back, 500);
    if (empty($front) || empty($back)) return false;
    
    $path = getDeckPath($deckId);
    if (!file_exists($path)) return false;
    
    $content = file_get_contents($path);
    $lines = explode("\n", $content);
    
    $image = basename($image);
    $audio = basename($audio);
    
    for ($i = 1; $i < count($lines); $i++) {
        if (strpos($lines[$i], $cardId . '|') === 0) {
            $lines[$i] = "$cardId|$front|$back|$image|$audio";
            file_put_contents($path, implode("\n", $lines), LOCK_EX);
            return true;
        }
    }
    return false;
}

function deleteCard($deckId, $cardId) {
    if (!validateDeckId($deckId) || !validateCardId($cardId)) return false;
    
    $path = getDeckPath($deckId);
    if (!file_exists($path)) return false;
    
    $content = file_get_contents($path);
    $lines = explode("\n", $content);
    
    for ($i = 1; $i < count($lines); $i++) {
        if (strpos($lines[$i], $cardId . '|') === 0) {
            // Delete media files
            $parts = explode('|', $lines[$i]);
            if (!empty($parts[3])) deleteMedia($parts[3]);
            if (!empty($parts[4])) deleteMedia($parts[4]);
            
            unset($lines[$i]);
            file_put_contents($path, implode("\n", $lines), LOCK_EX);
            return true;
        }
    }
    return false;
}

// Media Functions
function uploadMedia($file, $type = 'image') {
    if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        return '';
    }
    
    // Check file size
    if ($file['size'] > MAX_FILE_SIZE) {
        return '';
    }
    
    // Validate extension
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $allowedTypes = $type === 'image' ? ALLOWED_IMAGE_TYPES : ALLOWED_AUDIO_TYPES;
    
    if (!in_array($ext, $allowedTypes)) {
        return '';
    }
    
    // Validate MIME type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    $allowedMimes = [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp4'
    ];
    
    if (!in_array($mimeType, $allowedMimes)) {
        return '';
    }
    
    // Generate secure filename
    $filename = bin2hex(random_bytes(16)) . '.' . $ext;
    $path = MEDIA_DIR . '/' . $filename;
    
    if (move_uploaded_file($file['tmp_name'], $path)) {
        chmod($path, 0644);
        return $filename;
    }
    return '';
}

function deleteMedia($filename) {
    if (empty($filename)) return;
    
    // Security: Validate filename
    $filename = basename($filename);
    if (!preg_match('/^[a-f0-9]{32}\.(jpg|jpeg|png|gif|webp|mp3|wav|ogg|m4a)$/i', $filename)) {
        return;
    }
    
    $path = MEDIA_DIR . '/' . $filename;
    if (file_exists($path)) {
        unlink($path);
    }
}

function serveMedia($filename) {
    requireLogin();
    
    $filename = basename($filename);
    if (!preg_match('/^[a-f0-9]{32}\.(jpg|jpeg|png|gif|webp|mp3|wav|ogg|m4a)$/i', $filename)) {
        http_response_code(404);
        exit;
    }
    
    $path = MEDIA_DIR . '/' . $filename;
    if (!file_exists($path)) {
        http_response_code(404);
        exit;
    }
    
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $mimeTypes = [
        'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png',
        'gif' => 'image/gif', 'webp' => 'image/webp',
        'mp3' => 'audio/mpeg', 'wav' => 'audio/wav', 'ogg' => 'audio/ogg', 'm4a' => 'audio/mp4'
    ];
    
    header('Content-Type: ' . ($mimeTypes[$ext] ?? 'application/octet-stream'));
    header('Content-Length: ' . filesize($path));
    header('Cache-Control: private, max-age=3600');
    readfile($path);
    exit;
}

// Handle media serving
if (isset($_GET['media'])) {
    serveMedia($_GET['media']);
}

// Handle Actions
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    // CSRF Check for all authenticated actions
    if ($action !== 'register' && $action !== 'login') {
        if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
            $error = 'Invalid request. Please try again.';
            $action = '';
        }
    }
    
    if ($action === 'register') {
        if (!ALLOW_REGISTRATION) {
            $error = 'Registration is disabled. Please contact the administrator.';
        } elseif (!checkRateLimit('register', 3, 3600)) {
            $error = 'Too many registration attempts. Please try again later.';
        } elseif (registerUser($_POST['username'] ?? '', $_POST['password'] ?? '')) {
            $message = 'Registration successful! Please login.';
        } else {
            $error = 'Registration failed. Check requirements: username 3-50 chars (alphanumeric), password 8+ chars.';
        }
    } elseif ($action === 'login') {
        if (!checkRateLimit('login', 5, 900)) {
            $error = 'Too many login attempts. Please try again in 15 minutes.';
        } elseif (loginUser($_POST['username'] ?? '', $_POST['password'] ?? '')) {
            header('Location: index.php');
            exit;
        } else {
            $error = 'Invalid credentials.';
        }
    } elseif ($action === 'logout') {
        logout();
        header('Location: index.php');
        exit;
    }
    
    if (isLoggedIn()) {
        if ($action === 'create_deck') {
            $deckId = createDeck($_POST['deck_name'] ?? '');
            if ($deckId) {
                header('Location: index.php?page=deck&id=' . urlencode($deckId));
                exit;
            } else {
                $error = 'Failed to create deck.';
            }
        } elseif ($action === 'edit_deck') {
            if (updateDeck($_POST['deck_id'] ?? '', $_POST['deck_name'] ?? '')) {
                header('Location: index.php');
                exit;
            } else {
                $error = 'Failed to update deck.';
            }
        } elseif ($action === 'delete_deck') {
            deleteDeck($_POST['deck_id'] ?? '');
            header('Location: index.php');
            exit;
        } elseif ($action === 'add_card') {
            $image = !empty($_FILES['image']['tmp_name']) ? uploadMedia($_FILES['image'], 'image') : '';
            $audio = !empty($_FILES['audio']['tmp_name']) ? uploadMedia($_FILES['audio'], 'audio') : '';
            $deckId = $_POST['deck_id'] ?? '';
            if (addCard($deckId, $_POST['front'] ?? '', $_POST['back'] ?? '', $image, $audio)) {
                header('Location: index.php?page=deck&id=' . urlencode($deckId));
                exit;
            } else {
                $error = 'Failed to add card.';
            }
        } elseif ($action === 'edit_card') {
            $deckId = $_POST['deck_id'] ?? '';
            $cardId = $_POST['card_id'] ?? '';
            $cards = getCards($deckId);
            $currentCard = null;
            foreach ($cards as $card) {
                if ($card['id'] === $cardId) {
                    $currentCard = $card;
                    break;
                }
            }
            
            if ($currentCard) {
                $image = $currentCard['image'] ?? '';
                $audio = $currentCard['audio'] ?? '';
                
                if (isset($_POST['delete_image']) && $_POST['delete_image'] === '1') {
                    deleteMedia($image);
                    $image = '';
                } elseif (!empty($_FILES['image']['tmp_name'])) {
                    deleteMedia($image);
                    $image = uploadMedia($_FILES['image'], 'image');
                }
                
                if (isset($_POST['delete_audio']) && $_POST['delete_audio'] === '1') {
                    deleteMedia($audio);
                    $audio = '';
                } elseif (!empty($_FILES['audio']['tmp_name'])) {
                    deleteMedia($audio);
                    $audio = uploadMedia($_FILES['audio'], 'audio');
                }
                
                updateCard($deckId, $cardId, $_POST['front'] ?? '', $_POST['back'] ?? '', $image, $audio);
            }
            header('Location: index.php?page=deck&id=' . urlencode($deckId));
            exit;
        } elseif ($action === 'delete_card') {
            $deckId = $_POST['deck_id'] ?? '';
            deleteCard($deckId, $_POST['card_id'] ?? '');
            header('Location: index.php?page=deck&id=' . urlencode($deckId));
            exit;
        } elseif ($action === 'mark_card') {
            $result = saveProgress($_POST['deck_id'] ?? '', $_POST['card_id'] ?? '', $_POST['status'] ?? '');
            echo json_encode(['success' => $result]);
            exit;
        } elseif ($action === 'reset_progress') {
            $result = resetProgress($_POST['deck_id'] ?? '');
            echo json_encode(['success' => $result]);
            exit;
        }
    }
}

$page = $_GET['page'] ?? 'home';
$deckId = isset($_GET['id']) ? ($_GET['id']) : '';

// Validate deckId if present
if (!empty($deckId) && !validateDeckId($deckId)) {
    $error = 'Invalid deck ID';
    $page = 'home';
    $deckId = '';
}

$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Flashcard App</title>
    <link rel="stylesheet" href="styles.css">
    <meta name="robots" content="noindex, nofollow">
</head>
<body>
    <div class="container">
        <header>
            <h1>📚 Flashcard App</h1>
            <?php if (isLoggedIn()): ?>
                <div class="user-info">
                    <span>Welcome, <?= htmlspecialchars($_SESSION['user']) ?></span>
                    <form method="post" style="display: inline;">
                        <input type="hidden" name="action" value="logout">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <button type="submit" class="btn btn-small">Logout</button>
                    </form>
                </div>
            <?php endif; ?>
        </header>

        <?php if ($message): ?>
            <div class="message success"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="message error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <?php if (!isLoggedIn()): ?>
            <!-- Login/Register Page -->
            <div class="auth-container">
                <div class="auth-box">
                    <h2>Login</h2>
                    <form method="post">
                        <input type="hidden" name="action" value="login">
                        <input type="text" name="username" placeholder="Username" required autocomplete="username">
                        <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
                        <button type="submit" class="btn">Login</button>
                    </form>
                </div>
                
                <?php if (ALLOW_REGISTRATION): ?>
                <div class="auth-box">
                    <h2>Register</h2>
                    <form method="post">
                        <input type="hidden" name="action" value="register">
                        <input type="text" name="username" placeholder="Username (3-50 chars, alphanumeric)" required autocomplete="username">
                        <input type="password" name="password" placeholder="Password (min 8 chars)" required autocomplete="new-password">
                        <button type="submit" class="btn">Register</button>
                    </form>
                </div>
                <?php else: ?>
                <div class="auth-box">
                    <h2>Registration Disabled</h2>
                    <p class="info-text">Public registration is currently disabled. Please contact the administrator to create an account.</p>
                </div>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <?php if ($page === 'home'): ?>
                <!-- Decks List -->
                <div class="content">
                    <div class="section-header">
                        <h2>My Decks</h2>
                        <button onclick="showModal('createDeckModal')" class="btn">+ New Deck</button>
                    </div>
                    
                    <div class="decks-grid">
                        <?php $decks = getDecks(); ?>
                        <?php if (empty($decks)): ?>
                            <p class="empty-state">No decks yet. Create your first deck to get started!</p>
                        <?php else: ?>
                            <?php foreach ($decks as $deck): ?>
                                <div class="deck-card">
                                    <h3><?= htmlspecialchars($deck['name']) ?></h3>
                                    <div class="deck-stats">
                                        <div class="stat-item">
                                            <span class="stat-label">Total:</span>
                                            <span class="stat-value"><?= (int)$deck['stats']['total'] ?></span>
                                        </div>
                                        <div class="stat-item known">
                                            <span class="stat-label">✓ Known:</span>
                                            <span class="stat-value"><?= (int)$deck['stats']['known'] ?></span>
                                        </div>
                                        <div class="stat-item unknown">
                                            <span class="stat-label">✗ Unknown:</span>
                                            <span class="stat-value"><?= (int)$deck['stats']['unknown'] ?></span>
                                        </div>
                                        <div class="stat-item">
                                            <span class="stat-label">Not Reviewed:</span>
                                            <span class="stat-value"><?= (int)$deck['stats']['notReviewed'] ?></span>
                                        </div>
                                    </div>
                                    <div class="deck-actions">
                                        <a href="?page=deck&amp;id=<?= urlencode($deck['id']) ?>" class="btn btn-small">Open</a>
                                        <a href="?page=study&amp;id=<?= urlencode($deck['id']) ?>" class="btn btn-small btn-primary">Study</a>
                                        <button onclick="editDeck('<?= htmlspecialchars($deck['id'], ENT_QUOTES) ?>', '<?= htmlspecialchars($deck['name'], ENT_QUOTES) ?>')" class="btn btn-small">Edit</button>
                                        <button onclick="deleteDeck('<?= htmlspecialchars($deck['id'], ENT_QUOTES) ?>')" class="btn btn-small btn-danger">Delete</button>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>

            <?php elseif ($page === 'deck'): ?>
                <!-- Deck Details -->
                <?php
                $decks = getDecks();
                if (!isset($decks[$deckId])) {
                    echo '<div class="content"><p class="error">Deck not found.</p></div>';
                } else {
                    $deck = $decks[$deckId];
                    $cards = getCards($deckId);
                    $progress = getProgress($deckId);
                ?>
                    <div class="content">
                        <div class="breadcrumb">
                            <a href="index.php">← Back to Decks</a>
                        </div>
                        
                        <div class="section-header">
                            <div>
                                <h2><?= htmlspecialchars($deck['name']) ?></h2>
                                <div class="deck-stats-inline">
                                    <span>Total: <?= (int)$deck['stats']['total'] ?></span>
                                    <span class="known">✓ Known: <?= (int)$deck['stats']['known'] ?></span>
                                    <span class="unknown">✗ Unknown: <?= (int)$deck['stats']['unknown'] ?></span>
                                    <span>Not Reviewed: <?= (int)$deck['stats']['notReviewed'] ?></span>
                                </div>
                            </div>
                            <div>
                                <a href="?page=study&amp;id=<?= urlencode($deckId) ?>" class="btn btn-primary">Study Deck</a>
                                <button onclick="showModal('addCardModal')" class="btn">+ Add Card</button>
                            </div>
                        </div>
                        
                        <div class="cards-list">
                            <?php if (empty($cards)): ?>
                                <p class="empty-state">No cards yet. Add your first card!</p>
                            <?php else: ?>
                                <?php foreach ($cards as $card): ?>
                                    <?php
                                    $cardStatus = '';
                                    if (in_array($card['id'], $progress['known'])) {
                                        $cardStatus = 'known';
                                    } elseif (in_array($card['id'], $progress['unknown'])) {
                                        $cardStatus = 'unknown';
                                    }
                                    ?>
                                    <div class="card-item <?= htmlspecialchars($cardStatus) ?>">
                                        <div class="card-content">
                                            <div class="card-status-badge">
                                                <?php if ($cardStatus === 'known'): ?>
                                                    <span class="badge badge-known">✓ Known</span>
                                                <?php elseif ($cardStatus === 'unknown'): ?>
                                                    <span class="badge badge-unknown">✗ Unknown</span>
                                                <?php else: ?>
                                                    <span class="badge badge-new">New</span>
                                                <?php endif; ?>
                                            </div>
                                            <div class="card-side">
                                                <strong>Front:</strong> <?= htmlspecialchars($card['front']) ?>
                                            </div>
                                            <div class="card-side">
                                                <strong>Back:</strong> <?= htmlspecialchars($card['back']) ?>
                                            </div>
                                            <?php if ($card['image']): ?>
                                                <div class="card-media">
                                                    <img src="index.php?media=<?= urlencode($card['image']) ?>" alt="Card image">
                                                </div>
                                            <?php endif; ?>
                                            <?php if ($card['audio']): ?>
                                                <div class="card-media">
                                                    <audio controls src="index.php?media=<?= urlencode($card['audio']) ?>"></audio>
                                                </div>
                                            <?php endif; ?>
                                        </div>
                                        <div class="card-actions">
                                            <button onclick='editCard(<?= json_encode($card, JSON_HEX_APOS | JSON_HEX_QUOT) ?>, <?= json_encode($deckId, JSON_HEX_APOS | JSON_HEX_QUOT) ?>)' class="btn btn-small">Edit</button>
                                            <button onclick="deleteCard(<?= json_encode($deckId, JSON_HEX_APOS | JSON_HEX_QUOT) ?>, <?= json_encode($card['id'], JSON_HEX_APOS | JSON_HEX_QUOT) ?>)" class="btn btn-small btn-danger">Delete</button>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php } ?>

            <?php elseif ($page === 'study'): ?>
                <!-- Study Mode -->
                <?php
                $decks = getDecks();
                if (!isset($decks[$deckId])) {
                    echo '<div class="content"><p class="error">Deck not found.</p></div>';
                } else {
                    $deck = $decks[$deckId];
                    $cards = getCards($deckId);
                    $progress = getProgress($deckId);
                    if (empty($cards)) {
                        echo '<div class="content"><p class="empty-state">No cards to study. Add some cards first!</p></div>';
                    } else {
                ?>
                    <div class="content">
                        <div class="breadcrumb">
                            <a href="?page=deck&amp;id=<?= urlencode($deckId) ?>">← Back to Deck</a>
                        </div>
                        
                        <h2><?= htmlspecialchars($deck['name']) ?></h2>
                        
                        <div class="study-progress">
                            <span id="cardCounter">1 / <?= count($cards) ?></span>
                        </div>
                        
                        <div class="flashcard" id="flashcard" onclick="flipCard()">
    <div class="flashcard-inner">
        <div class="flashcard-front">
            <div class="card-text" id="frontText"></div>
            <div id="frontMedia"></div>
            <div id="frontAudio"></div>
            <div class="flip-hint">Click to flip</div>
        </div>
        <div class="flashcard-back">
            <div class="card-text" id="backText"></div>
            <div id="backAudio"></div>
            <div class="flip-hint">Click to flip back</div>
        </div>
    </div>
</div>
                        
                        <div class="study-actions">
                            <button onclick="markCard('unknown')" class="btn btn-danger btn-large">❌ Don't Know</button>
                            <button onclick="nextCard()" class="btn btn-large">⏭️ Skip</button>
                            <button onclick="markCard('known')" class="btn btn-success btn-large">✓ I Know This</button>
                        </div>
                        
                        <div class="study-stats">
                            <div class="stat-box">
                                <div class="stat-number" id="totalCards"><?= count($cards) ?></div>
                                <div class="stat-label">Total Cards</div>
                            </div>
                            <div class="stat-box known">
                                <div class="stat-number" id="knownCount"><?= $deck['stats']['known'] ?></div>
                                <div class="stat-label">Known</div>
                            </div>
                            <div class="stat-box unknown">
                                <div class="stat-number" id="unknownCount"><?= $deck['stats']['unknown'] ?></div>
                                <div class="stat-label">Unknown</div>
                            </div>
                            <div class="stat-box">
                                <div class="stat-number" id="notReviewedCount"><?= $deck['stats']['notReviewed'] ?></div>
                                <div class="stat-label">Not Reviewed</div>
                            </div>
                        </div>
                        
                        <div class="study-controls">
                            <button onclick="shuffleCards()" class="btn">🔀 Shuffle</button>
                            <button onclick="toggleUnknownOnly()" class="btn" id="unknownBtn">Review Unknown Only</button>
                            <button onclick="resetProgress()" class="btn btn-danger">Reset All Progress</button>
                        </div>
                    </div>
                    
                    <script>
                        const deckId = <?= json_encode($deckId) ?>;
                        const csrfToken = <?= json_encode($csrfToken) ?>;
                        let allCards = <?= json_encode($cards) ?>;
                        let cards = [...allCards];
                        let currentIndex = 0;
                        let isFlipped = false;
                        let knownCards = new Set(<?= json_encode($progress['known']) ?>);
                        let unknownCards = new Set(<?= json_encode($progress['unknown']) ?>);
                        let showUnknownOnly = false;
                        
                        function updateStats() {
                            const total = allCards.length;
                            const known = knownCards.size;
                            const unknown = unknownCards.size;
                            const notReviewed = total - known - unknown;
                            
                            document.getElementById('totalCards').textContent = total;
                            document.getElementById('knownCount').textContent = known;
                            document.getElementById('unknownCount').textContent = unknown;
                            document.getElementById('notReviewedCount').textContent = notReviewed;
                        }
                        
  function displayCard() {
    if (cards.length === 0) {
        document.getElementById('flashcard').innerHTML = '<div class="completion-message"><h3>🎉 All done!</h3><p>You\'ve reviewed all cards in this mode.</p></div>';
        document.querySelector('.study-actions').style.display = 'none';
        return;
    }
    
    const card = cards[currentIndex];
    document.getElementById('frontText').textContent = card.front;
    document.getElementById('backText').textContent = card.back;
    
    // Display image
    let imageHtml = '';
    if (card.image) {
        const imageUrl = 'index.php?media=' + encodeURIComponent(card.image);
        imageHtml = `<img src="${imageUrl}" alt="Card image">`;
    }
    document.getElementById('frontMedia').innerHTML = imageHtml;
    
    // Display audio on both sides
    let audioHtml = '';
    if (card.audio) {
        const audioUrl = 'index.php?media=' + encodeURIComponent(card.audio);
        audioHtml = `<audio controls src="${audioUrl}"></audio>`;
    }
    document.getElementById('frontAudio').innerHTML = audioHtml;
    document.getElementById('backAudio').innerHTML = audioHtml;
    
    document.getElementById('cardCounter').textContent = `${currentIndex + 1} / ${cards.length}`;
    
    if (isFlipped) {
        document.getElementById('flashcard').classList.remove('flipped');
        isFlipped = false;
    }
}
                        
                        function flipCard() {
                            document.getElementById('flashcard').classList.toggle('flipped');
                            isFlipped = !isFlipped;
                        }
                        
                        function nextCard() {
                            if (currentIndex < cards.length - 1) {
                                currentIndex++;
                            } else {
                                currentIndex = 0;
                            }
                            displayCard();
                        }
                        
                        async function markCard(status) {
                            const cardId = cards[currentIndex].id;
                            
                            // Update local tracking
                            if (status === 'known') {
                                knownCards.add(cardId);
                                unknownCards.delete(cardId);
                            } else if (status === 'unknown') {
                                unknownCards.add(cardId);
                                knownCards.delete(cardId);
                            }
                            
                            // Save to server
                            const formData = new FormData();
                            formData.append('action', 'mark_card');
                            formData.append('deck_id', deckId);
                            formData.append('card_id', cardId);
                            formData.append('status', status);
                            formData.append('csrf_token', csrfToken);
                            
                            try {
                                await fetch('index.php', {
                                    method: 'POST',
                                    body: formData
                                });
                            } catch (e) {
                                console.error('Failed to save progress', e);
                            }
                            
                            updateStats();
                            
                            // If in "unknown only" mode and card is marked as known, remove it from current deck
                            if (showUnknownOnly && status === 'known') {
                                cards.splice(currentIndex, 1);
                                if (currentIndex >= cards.length) {
                                    currentIndex = 0;
                                }
                            } else {
                                nextCard();
                            }
                            
                            displayCard();
                        }
                        
                        function shuffleCards() {
                            for (let i = cards.length - 1; i > 0; i--) {
                                const j = Math.floor(Math.random() * (i + 1));
                                [cards[i], cards[j]] = [cards[j], cards[i]];
                            }
                            currentIndex = 0;
                            displayCard();
                        }
                        
                        function toggleUnknownOnly() {
                            showUnknownOnly = !showUnknownOnly;
                            const btn = document.getElementById('unknownBtn');
                            
                            if (showUnknownOnly) {
                                cards = allCards.filter(c => unknownCards.has(c.id) || (!knownCards.has(c.id) && !unknownCards.has(c.id)));
                                btn.textContent = 'Show All Cards';
                                btn.classList.add('btn-primary');
                            } else {
                                cards = [...allCards];
                                btn.textContent = 'Review Unknown Only';
                                btn.classList.remove('btn-primary');
                            }
                            
                            currentIndex = 0;
                            displayCard();
                        }
                        
                        async function resetProgress() {
                            if (!confirm('This will reset ALL progress for this deck. Are you sure?')) {
                                return;
                            }
                            
                            const formData = new FormData();
                            formData.append('action', 'reset_progress');
                            formData.append('deck_id', deckId);
                            formData.append('csrf_token', csrfToken);
                            
                            try {
                                await fetch('index.php', {
                                    method: 'POST',
                                    body: formData
                                });
                            } catch (e) {
                                console.error('Failed to reset progress', e);
                            }
                            
                            knownCards.clear();
                            unknownCards.clear();
                            showUnknownOnly = false;
                            cards = [...allCards];
                            currentIndex = 0;
                            document.getElementById('unknownBtn').textContent = 'Review Unknown Only';
                            document.getElementById('unknownBtn').classList.remove('btn-primary');
                            document.querySelector('.study-actions').style.display = 'flex';
                            updateStats();
                            displayCard();
                        }
                        
                        updateStats();
                        displayCard();
                    </script>
                <?php
                    }
                }
                ?>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <!-- Modals -->
    <div id="createDeckModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('createDeckModal')">&times;</span>
            <h2>Create New Deck</h2>
            <form method="post">
                <input type="hidden" name="action" value="create_deck">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                <input type="text" name="deck_name" placeholder="Deck Name" required maxlength="200">
                <button type="submit" class="btn">Create</button>
            </form>
        </div>
    </div>

    <div id="editDeckModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('editDeckModal')">&times;</span>
            <h2>Edit Deck</h2>
            <form method="post">
                <input type="hidden" name="action" value="edit_deck">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                <input type="hidden" name="deck_id" id="editDeckId">
                <input type="text" name="deck_name" id="editDeckName" required maxlength="200">
                <button type="submit" class="btn">Save</button>
            </form>
        </div>
    </div>

    <div id="addCardModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('addCardModal')">&times;</span>
            <h2>Add Card</h2>
            <form method="post" enctype="multipart/form-data">
                <input type="hidden" name="action" value="add_card">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                <input type="hidden" name="deck_id" value="<?= htmlspecialchars($deckId) ?>">
                <input type="text" name="front" placeholder="Front (e.g., English word)" required maxlength="500">
                <input type="text" name="back" placeholder="Back (e.g., Translation)" required maxlength="500">
                <label>Image (JPG, PNG, GIF, WebP - max 5MB):</label>
                <input type="file" name="image" accept=".jpg,.jpeg,.png,.gif,.webp">
                <label>Audio (MP3, WAV, OGG, M4A - max 5MB):</label>
                <input type="file" name="audio" accept=".mp3,.wav,.ogg,.m4a">
                <button type="submit" class="btn">Add Card</button>
            </form>
        </div>
    </div>

    <div id="editCardModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('editCardModal')">&times;</span>
            <h2>Edit Card</h2>
            <form method="post" enctype="multipart/form-data">
                <input type="hidden" name="action" value="edit_card">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                <input type="hidden" name="deck_id" id="editCardDeckId">
                <input type="hidden" name="card_id" id="editCardId">
                <input type="text" name="front" id="editCardFront" required maxlength="500">
                <input type="text" name="back" id="editCardBack" required maxlength="500">
                
                <div id="currentImage"></div>
                <label>New Image (JPG, PNG, GIF, WebP - max 5MB):</label>
                <input type="file" name="image" accept=".jpg,.jpeg,.png,.gif,.webp">
                
                <div id="currentAudio"></div>
                <label>New Audio (MP3, WAV, OGG, M4A - max 5MB):</label>
                <input type="file" name="audio" accept=".mp3,.wav,.ogg,.m4a">
                
                <button type="submit" class="btn">Save Changes</button>
            </form>
        </div>
    </div>

    <script>
        function showModal(id) {
            document.getElementById(id).style.display = 'block';
        }
        
        function closeModal(id) {
            document.getElementById(id).style.display = 'none';
        }
        
        function editDeck(id, name) {
            document.getElementById('editDeckId').value = id;
            document.getElementById('editDeckName').value = name;
            showModal('editDeckModal');
        }
        
        function deleteDeck(id) {
            if (confirm('Delete this deck and all its cards?')) {
                const form = document.createElement('form');
                form.method = 'post';
                form.innerHTML = `
                    <input type="hidden" name="action" value="delete_deck">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    <input type="hidden" name="deck_id" value="${id}">
                `;
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        function editCard(card, deckId) {
            document.getElementById('editCardDeckId').value = deckId;
            document.getElementById('editCardId').value = card.id;
            document.getElementById('editCardFront').value = card.front;
            document.getElementById('editCardBack').value = card.back;
            
            let imageHtml = '';
            if (card.image) {
                imageHtml = `
                    <div class="current-media">
                        <img src="index.php?media=${encodeURIComponent(card.image)}" style="max-width: 200px;">
                        <label><input type="checkbox" name="delete_image" value="1"> Delete image</label>
                    </div>
                `;
            }
            document.getElementById('currentImage').innerHTML = imageHtml;
            
            let audioHtml = '';
            if (card.audio) {
                audioHtml = `
                    <div class="current-media">
                        <audio controls src="index.php?media=${encodeURIComponent(card.audio)}"></audio>
                        <label><input type="checkbox" name="delete_audio" value="1"> Delete audio</label>
                    </div>
                `;
            }
            document.getElementById('currentAudio').innerHTML = audioHtml;
            
            showModal('editCardModal');
        }
        
        function deleteCard(deckId, cardId) {
            if (confirm('Delete this card?')) {
                const form = document.createElement('form');
                form.method = 'post';
                form.innerHTML = `
                    <input type="hidden" name="action" value="delete_card">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                    <input type="hidden" name="deck_id" value="${deckId}">
                    <input type="hidden" name="card_id" value="${cardId}">
                `;
                document.body.appendChild(form);
                form.submit();
            }
        }
        
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display = 'none';
            }
        }
    </script>
</body>
</html>
