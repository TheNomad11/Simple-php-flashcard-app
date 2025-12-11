<?php
/**
 * Flashcard Learning Application - Enhanced Security Version
 * Part 1: Configuration, Security, and Authentication
 */

// HTTPS Enforcement (Comment out if testing on localhost without SSL)
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
    if ($_SERVER['SERVER_NAME'] !== 'localhost' && $_SERVER['SERVER_NAME'] !== '127.0.0.1') {
        header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
        exit;
    }
}

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

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self' blob:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'");


// Security: Regenerate session ID periodically
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
    $_SESSION['created_at'] = time();
}

// Regenerate session ID every 30 minutes
if (isset($_SESSION['created_at']) && (time() - $_SESSION['created_at'] > 1800)) {
    session_regenerate_id(true);
    $_SESSION['created_at'] = time();
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
define('LOG_FILE', DATA_DIR . '/security.log');

// Security: Allowed file extensions
define('ALLOWED_IMAGE_TYPES', 'jpg,jpeg,png,gif,webp');
define('ALLOWED_AUDIO_TYPES', 'mp3,wav,ogg,m4a,webm');

define('MAX_FILE_SIZE', 5242880); // 5MB

// Registration Settings
define('ALLOW_REGISTRATION', false);  // Set to false to disable public registration

// Read-Only Mode Settings
define('READ_ONLY_MODE', false);     // Set to true for public viewing (no editing)
define('REQUIRE_LOGIN_TO_VIEW', true); // Set to false to allow viewing without login

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

// Security Logging
function logSecurityEvent($event, $details = []) {
    $logEntry = date('Y-m-d H:i:s') . ' | ' . $event . ' | ' . 
                json_encode($details) . ' | IP: ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . 
                ' | User: ' . ($_SESSION['user'] ?? 'guest') . "\n";
    @file_put_contents(LOG_FILE, $logEntry, FILE_APPEND | LOCK_EX);
}

// CSRF Protection with Rotation
function generateCSRFToken() {
    // Rotate token every 2 hours or if missing
    if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_token_time']) || 
        (time() - $_SESSION['csrf_token_time'] > 7200)) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    return $_SESSION['csrf_token'];
}

function verifyCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Rate Limiting (enhanced with cleanup)
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
        logSecurityEvent('rate_limit_exceeded', ['action' => $action]);
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
    // Exact format from bin2hex(random_bytes(8)) = 16 hex chars
    if (!preg_match('/^[a-f0-9]{16}$/', $cardId)) {
        return false;
    }
    return true;
}

// Enhanced escape/unescape using base64 to prevent corruption
function escapeFileData($string) {
    return base64_encode($string);
}

function unescapeFileData($string) {
    return base64_decode($string);
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
    
    // Lock file for reading and writing
    $fp = fopen(USERS_FILE, 'c+');
    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) fclose($fp);
        return false;
    }
    
    // Check if user exists
    $users = [];
    while (($line = fgets($fp)) !== false) {
        $line = trim($line);
        if (empty($line)) continue;
        list($u, $p) = explode(':', $line, 2);
        if ($u === $username) {
            flock($fp, LOCK_UN);
            fclose($fp);
            logSecurityEvent('registration_failed_duplicate', ['username' => $username]);
            return false;
        }
        $users[] = $line;
    }
    
    // Add new user
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $users[] = "$username:$hash";
    
    // Write back
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, implode("\n", $users) . "\n");
    
    flock($fp, LOCK_UN);
    fclose($fp);
    
    logSecurityEvent('user_registered', ['username' => $username]);
    return true;
}

function loginUser($username, $password) {
    if (!file_exists(USERS_FILE)) return false;
    
    $username = sanitizeInput($username, 50);
    
    $fp = fopen(USERS_FILE, 'r');
    if (!$fp) return false;
    
    flock($fp, LOCK_SH);
    
    $authenticated = false;
    while (($line = fgets($fp)) !== false) {
        $line = trim($line);
        if (empty($line)) continue;
        list($u, $h) = explode(':', $line, 2);
        if ($u === $username && password_verify($password, $h)) {
            $authenticated = true;
            break;
        }
    }
    
    flock($fp, LOCK_UN);
    fclose($fp);
    
    if ($authenticated) {
        // Security: Regenerate session ID on login
        session_regenerate_id(true);
        $_SESSION['user'] = $username;
        $_SESSION['login_time'] = time();
        logSecurityEvent('login_success', ['username' => $username]);
        return true;
    } else {
        logSecurityEvent('login_failed', ['username' => $username]);
        return false;
    }
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
    $username = $_SESSION['user'] ?? 'unknown';
    session_unset();
    session_destroy();
    logSecurityEvent('user_logout', ['username' => $username]);
}

function getCurrentUser() {
    return $_SESSION['user'] ?? null;
}


/**
 * Part 2: Deck and Card Management Functions with Ownership Control
 * 
 * IMPORTANT: This is Part 2 of 3. Append this after Part 1.
 */

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
    
    $fp = fopen($file, 'r');
    if (!$fp) return ['known' => [], 'unknown' => []];
    
    flock($fp, LOCK_SH);
    $content = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    
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
    
    $fp = fopen($file, 'c+');
    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) fclose($fp);
        return false;
    }
    
    // Read current progress
    $progress = ['known' => [], 'unknown' => []];
    while (($line = fgets($fp)) !== false) {
        $line = trim($line);
        if (empty($line)) continue;
        $parts = explode('|', $line);
        if (count($parts) !== 2) continue;
        
        $id = $parts[0];
        $st = $parts[1];
        
        if (!validateCardId($id)) continue;
        if ($id === $cardId) continue; // Remove old entry for this card
        
        if ($st === 'known') {
            $progress['known'][] = $id;
        } elseif ($st === 'unknown') {
            $progress['unknown'][] = $id;
        }
    }
    
    // Add new entry
    if ($status === 'known') {
        $progress['known'][] = $cardId;
    } elseif ($status === 'unknown') {
        $progress['unknown'][] = $cardId;
    }
    
    // Write back
    $lines = [];
    foreach ($progress['known'] as $id) {
        $lines[] = "$id|known";
    }
    foreach ($progress['unknown'] as $id) {
        $lines[] = "$id|unknown";
    }
    
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, implode("\n", $lines));
    
    flock($fp, LOCK_UN);
    fclose($fp);
    
    @chmod($file, 0644);
    return true;
}

function resetProgress($deckId) {
    if (!validateDeckId($deckId)) {
        return false;
    }
    $file = getProgressFile($deckId);
    if (file_exists($file)) {
        if (!@unlink($file)) {
            logSecurityEvent('file_delete_failed', ['file' => basename($file)]);
            return false;
        }
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

// Deck Functions with Ownership
function getDeckPath($deckId) {
    if (!validateDeckId($deckId)) {
        die('Invalid deck ID');
    }
    return DECKS_DIR . '/' . $deckId . '.txt';
}

function getDeckOwner($deckId) {
    $path = getDeckPath($deckId);
    if (!file_exists($path)) return null;
    
    $fp = fopen($path, 'r');
    if (!$fp) return null;
    
    flock($fp, LOCK_SH);
    $firstLine = fgets($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    
    if (!$firstLine) return null;
    
    // Format: deckname|owner
    $parts = explode('|', trim($firstLine));
    return isset($parts[1]) ? $parts[1] : null;
}

function checkDeckAccess($deckId, $requireOwner = false) {
    $owner = getDeckOwner($deckId);
    if ($owner === null) return false;
    
    $currentUser = getCurrentUser();
    if (!$currentUser) return false;
    
    if ($requireOwner) {
        return $owner === $currentUser;
    }
    
    // For now, all logged-in users can view all decks
    // You can modify this to implement sharing permissions later
    return true;
}

function getDecks() {
    $decks = [];
    if (!is_dir(DECKS_DIR)) return $decks;
    
    foreach (glob(DECKS_DIR . '/*.txt') as $file) {
        $deckId = basename($file, '.txt');
        if (!validateDeckId($deckId)) continue;
        
        $fp = fopen($file, 'r');
        if (!$fp) continue;
        
        flock($fp, LOCK_SH);
        $firstLine = fgets($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        
        if (!$firstLine) continue;
        
        $parts = explode('|', trim($firstLine));
        $deckName = isset($parts[0]) ? sanitizeInput($parts[0], 200) : $deckId;
        $owner = isset($parts[1]) ? $parts[1] : 'unknown';
        
        $stats = getDeckStats($deckId);
        $decks[$deckId] = [
            'name' => $deckName,
            'id' => $deckId,
            'owner' => $owner,
            'stats' => $stats,
            'isOwner' => ($owner === getCurrentUser())
        ];
    }
    return $decks;
}

function createDeck($name) {
    $name = sanitizeInput($name, 200);
    if (empty($name)) return false;
    
    $owner = getCurrentUser();
    if (!$owner) return false;
    
    $deckId = preg_replace('/[^a-z0-9_-]/', '_', strtolower($name)) . '_' . bin2hex(random_bytes(4));
    $path = getDeckPath($deckId);
    
    // Format: deckname|owner
    $firstLine = $name . '|' . $owner . "\n";
    
    if (!@file_put_contents($path, $firstLine, LOCK_EX)) {
        logSecurityEvent('deck_create_failed', ['deck_id' => $deckId]);
        return false;
    }
    
    @chmod($path, 0644);
    logSecurityEvent('deck_created', ['deck_id' => $deckId, 'name' => $name]);
    return $deckId;
}

function updateDeck($deckId, $name) {
    if (!validateDeckId($deckId)) return false;
    if (!checkDeckAccess($deckId, true)) return false;
    
    $name = sanitizeInput($name, 200);
    if (empty($name)) return false;
    
    $path = getDeckPath($deckId);
    if (!file_exists($path)) return false;
    
    $fp = fopen($path, 'r+');
    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) fclose($fp);
        return false;
    }
    
    $lines = [];
    $firstLine = true;
    while (($line = fgets($fp)) !== false) {
        if ($firstLine) {
            $parts = explode('|', trim($line));
            $owner = isset($parts[1]) ? $parts[1] : getCurrentUser();
            $lines[] = $name . '|' . $owner;
            $firstLine = false;
        } else {
            $lines[] = trim($line);
        }
    }
    
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, implode("\n", $lines));
    
    flock($fp, LOCK_UN);
    fclose($fp);
    
    logSecurityEvent('deck_updated', ['deck_id' => $deckId]);
    return true;
}

function deleteDeck($deckId) {
    if (!validateDeckId($deckId)) return false;
    if (!checkDeckAccess($deckId, true)) return false;
    
    $path = getDeckPath($deckId);
    if (file_exists($path)) {
        // Delete all media files first
        $cards = getCards($deckId);
        foreach ($cards as $card) {
            if (!empty($card['image'])) deleteMedia($card['image'], $deckId);
            if (!empty($card['audio'])) deleteMedia($card['audio'], $deckId);
        }
        
        if (!@unlink($path)) {
            logSecurityEvent('deck_delete_failed', ['deck_id' => $deckId]);
            return false;
        }
        
        // Also delete progress file
        $progressFile = getProgressFile($deckId);
        if (file_exists($progressFile)) {
            @unlink($progressFile);
        }
        
        logSecurityEvent('deck_deleted', ['deck_id' => $deckId]);
        return true;
    }
    return false;
}

// Card Functions
function getCards($deckId) {
    if (!validateDeckId($deckId)) return [];
    if (!checkDeckAccess($deckId, false)) return [];
    
    $path = getDeckPath($deckId);
    if (!file_exists($path)) return [];
    
    $fp = fopen($path, 'r');
    if (!$fp) return [];
    
    flock($fp, LOCK_SH);
    
    $cards = [];
    $firstLine = true;
    while (($line = fgets($fp)) !== false) {
        if ($firstLine) {
            $firstLine = false;
            continue; // Skip deck name/owner line
        }
        
        $line = trim($line);
        if ($line === '') continue;
        
        $parts = explode('|', $line);
        if (count($parts) >= 3) {
            $cardId = $parts[0];
            if (!validateCardId($cardId)) continue;
            
            $cards[] = [
                'id' => $cardId,
                'front' => sanitizeInput(unescapeFileData($parts[1]), 1000),
                'back' => sanitizeInput(unescapeFileData($parts[2]), 1000),
                'image' => isset($parts[3]) ? basename($parts[3]) : '',
                'audio' => isset($parts[4]) ? basename($parts[4]) : ''
            ];
        }
    }
    
    flock($fp, LOCK_UN);
    fclose($fp);
    
    return $cards;
}

function addCard($deckId, $front, $back, $image = '', $audio = '') {
    if (!validateDeckId($deckId)) return false;
    if (!checkDeckAccess($deckId, true)) return false;
    
    $front = sanitizeInput($front, 1000);
    $back = sanitizeInput($back, 1000);
    if (empty($front) || empty($back)) return false;
    
    $path = getDeckPath($deckId);
    if (!file_exists($path)) return false;
    
    $cardId = bin2hex(random_bytes(8));
    $image = basename($image);
    $audio = basename($audio);
    
    // Escape data before saving
    $escapedFront = escapeFileData($front);
    $escapedBack = escapeFileData($back);
    
    $line = "\n$cardId|$escapedFront|$escapedBack|$image|$audio";
    
    if (!@file_put_contents($path, $line, FILE_APPEND | LOCK_EX)) {
        logSecurityEvent('card_add_failed', ['deck_id' => $deckId]);
        return false;
    }
    
    return $cardId;
}

function updateCard($deckId, $cardId, $front, $back, $image = '', $audio = '') {
    if (!validateDeckId($deckId) || !validateCardId($cardId)) return false;
    if (!checkDeckAccess($deckId, true)) return false;
    
    $front = sanitizeInput($front, 1000);
    $back = sanitizeInput($back, 1000);
    if (empty($front) || empty($back)) return false;
    
    $path = getDeckPath($deckId);
    if (!file_exists($path)) return false;
    
    $fp = fopen($path, 'r+');
    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) fclose($fp);
        return false;
    }
    
    $image = basename($image);
    $audio = basename($audio);
    
    $escapedFront = escapeFileData($front);
    $escapedBack = escapeFileData($back);
    
    $lines = [];
    $found = false;
    while (($line = fgets($fp)) !== false) {
        $line = trim($line);
        if (strpos($line, $cardId . '|') === 0) {
            $lines[] = "$cardId|$escapedFront|$escapedBack|$image|$audio";
            $found = true;
        } else {
            $lines[] = $line;
        }
    }
    
    if (!$found) {
        flock($fp, LOCK_UN);
        fclose($fp);
        return false;
    }
    
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, implode("\n", $lines));
    
    flock($fp, LOCK_UN);
    fclose($fp);
    
    return true;
}

function deleteCard($deckId, $cardId) {
    if (!validateDeckId($deckId) || !validateCardId($cardId)) return false;
    if (!checkDeckAccess($deckId, true)) return false;
    
    $path = getDeckPath($deckId);
    if (!file_exists($path)) return false;
    
    $fp = fopen($path, 'r+');
    if (!$fp || !flock($fp, LOCK_EX)) {
        if ($fp) fclose($fp);
        return false;
    }
    
    $lines = [];
    $deleted = false;
    while (($line = fgets($fp)) !== false) {
        $line = trim($line);
        if (strpos($line, $cardId . '|') === 0) {
            // Delete media files
            $parts = explode('|', $line);
            if (!empty($parts[3])) deleteMedia($parts[3], $deckId);
            if (!empty($parts[4])) deleteMedia($parts[4], $deckId);
            $deleted = true;
            continue; // Skip this line
        }
        $lines[] = $line;
    }
    
    if (!$deleted) {
        flock($fp, LOCK_UN);
        fclose($fp);
        return false;
    }
    
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, implode("\n", $lines));
    
    flock($fp, LOCK_UN);
    fclose($fp);
    
    return true;
}


/**
 * Part 3: Media Functions, Request Handling, and HTML Output
 * 
 * IMPORTANT: This is Part 3 of 3. Append this after Part 2.
 * This part continues from Part 2 and includes the complete HTML output.
 */

// Media Functions with Access Control
function uploadMedia($file, $type = 'image', $deckId = null) {
    if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        return '';
    }
    
    // Check file size
    if ($file['size'] > MAX_FILE_SIZE) {
        logSecurityEvent('media:upload_size_exceeded', ['size' => $file['size']]);
        return '';
    }
    
    // Validate extension
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $allowedTypes = ($type === 'image') ? explode(',', ALLOWED_IMAGE_TYPES) : explode(',', ALLOWED_AUDIO_TYPES);
    if (!in_array($ext, $allowedTypes)) {
        logSecurityEvent('media:upload_invalid_extension', ['ext' => $ext]);
        return '';
    }
    
    // Validate MIME type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    $allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 
                     'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp4', 
                     'audio/webm', 'video/webm']; // WebM can be detected as video/webm even for audio-only
    
    if (!in_array($mimeType, $allowedMimes)) {
        logSecurityEvent('media:upload_invalid_mime', ['mime' => $mimeType]);
        return '';
    }
    
    // Generate secure filename WITH deck ID for fast access control
    if ($deckId && validateDeckId($deckId)) {
        $filename = bin2hex(random_bytes(16)) . '_' . $deckId . '.' . $ext;
    } else {
        // Fallback for old code or missing deckId
        $filename = bin2hex(random_bytes(16)) . '.' . $ext;
    }
    $path = MEDIA_DIR . '/' . $filename;
    
    if (move_uploaded_file($file['tmp_name'], $path)) {
        chmod($path, 0644);
        logSecurityEvent('media:uploaded', ['filename' => $filename, 'type' => $type, 'deckid' => $deckId]);
        return $filename;
    }
    
    logSecurityEvent('media:upload_failed', ['filename' => $filename]);
    return '';
}

function deleteMedia($filename, $deckId = null) {
    if (empty($filename)) return;
    
    // Security: Validate filename (supports both old and new format with deck ID)
    $filename = basename($filename);
    if (!preg_match('/^[a-f0-9]{32}(_[a-zA-Z0-9_-]+)?\.(jpg|jpeg|png|gif|webp|mp3|wav|ogg|m4a|webm)$/i', $filename)) {
        return;
    }
    
    // Verify ownership if deckId provided
    if ($deckId && !checkDeckAccess($deckId, true)) {
        logSecurityEvent('media:delete_access_denied', ['filename' => $filename, 'deckid' => $deckId]);
        return;
    }
    
    $path = MEDIA_DIR . '/' . $filename;
    if (file_exists($path)) {
        if (!unlink($path)) {
            logSecurityEvent('media:delete_failed', ['filename' => $filename]);
        }
    }
}


function serveMedia($filename) {
    requireLogin();
    
    $filename = basename($filename);
    
    // Try to extract deck ID from filename (new format: hash_deckid.ext)
    if (preg_match('/^[a-f0-9]{32}_([a-zA-Z0-9_-]+)\.(jpg|jpeg|png|gif|webp|mp3|wav|ogg|m4a|webm)$/i', $filename, $matches)) {
        // NEW FORMAT: Fast access check using embedded deck ID
        $deckId = $matches[1];
        
        if (!validateDeckId($deckId) || !checkDeckAccess($deckId, false)) {
            logSecurityEvent('media:access_denied', ['filename' => $filename, 'deckid' => $deckId]);
            http_response_code(403);
            exit;
        }
        
        $path = MEDIA_DIR . '/' . $filename;
        if (!file_exists($path)) {
            http_response_code(404);
            exit;
        }
        
        // Serve file
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $mimeTypes = [
            'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png',
            'gif' => 'image/gif', 'webp' => 'image/webp', 'mp3' => 'audio/mpeg',
            'wav' => 'audio/wav', 'ogg' => 'audio/ogg', 'm4a' => 'audio/mp4',
            'webm' => 'audio/webm'
        ];
        
        header('Content-Type: ' . ($mimeTypes[$ext] ?? 'application/octet-stream'));
        header('Content-Length: ' . filesize($path));
        header('Cache-Control: private, max-age=3600');
        readfile($path);
        exit;
        
    } elseif (preg_match('/^[a-f0-9]{32}\.(jpg|jpeg|png|gif|webp|mp3|wav|ogg|m4a|webm)$/i', $filename)) {
        // OLD FORMAT: Fallback to slow check for backward compatibility
        $path = MEDIA_DIR . '/' . $filename;
        if (!file_exists($path)) {
            http_response_code(404);
            exit;
        }
        
        // Verify user has access to this media file (old slow method)
        $hasAccess = false;
        $decks = getDecks();
        foreach ($decks as $deck) {
            $cards = getCards($deck['id']);
            foreach ($cards as $card) {
                if ($card['image'] === $filename || $card['audio'] === $filename) {
                    $hasAccess = true;
                    break 2;
                }
            }
        }
        
        if (!$hasAccess) {
            logSecurityEvent('media:access_denied', ['filename' => $filename]);
            http_response_code(403);
            exit;
        }
        
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $mimeTypes = [
            'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png',
            'gif' => 'image/gif', 'webp' => 'image/webp', 'mp3' => 'audio/mpeg',
            'wav' => 'audio/wav', 'ogg' => 'audio/ogg', 'm4a' => 'audio/mp4',
            'webm' => 'audio/webm'
        ];
        
        header('Content-Type: ' . ($mimeTypes[$ext] ?? 'application/octet-stream'));
        header('Content-Length: ' . filesize($path));
        header('Cache-Control: private, max-age=3600');
        readfile($path);
        exit;
        
    } else {
        // Invalid filename format
        logSecurityEvent('media:access_invalid_filename', ['filename' => $filename]);
        http_response_code(404);
        exit;
    }
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
            logSecurityEvent('csrf_token_mismatch', ['action' => $action]);
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
            if (!checkRateLimit('create_deck', 10, 300)) {
                $error = 'Too many deck creations. Please slow down.';
            } else {
                $deckId = createDeck($_POST['deck_name'] ?? '');
                if ($deckId) {
                    header('Location: index.php?page=deck&id=' . urlencode($deckId));
                    exit;
                } else {
                    $error = 'Failed to create deck.';
                }
            }
        } elseif ($action === 'edit_deck') {
            if (updateDeck($_POST['deck_id'] ?? '', $_POST['deck_name'] ?? '')) {
                header('Location: index.php');
                exit;
            } else {
                $error = 'Failed to update deck. Check permissions.';
            }
        } elseif ($action === 'delete_deck') {
            if (deleteDeck($_POST['deck_id'] ?? '')) {
                header('Location: index.php');
                exit;
            } else {
                $error = 'Failed to delete deck. Check permissions.';
            }
  } elseif ($action === 'add_card') {
    $deckId = $_POST['deck_id'] ?? '';
    if (!checkRateLimit('add_card_' . $deckId, 30, 60)) {
        $error = 'Too many card additions. Please slow down.';
    } else {
        $image = !empty($_FILES['image']['tmp_name']) ? uploadMedia($_FILES['image'], 'image', $deckId) : '';
        
        // With this more robust check:
        $audio = '';
        if (!empty($_FILES['audio']['tmp_name']) || !empty($_POST['audio'])) {
            // Handle both traditional file upload and fetch API submission
            if (!empty($_FILES['audio']['tmp_name'])) {
                $audio = uploadMedia($_FILES['audio'], 'audio', $deckId);
            } else {
                // Handle audio data from fetch API
                $audioData = file_get_contents('php://input');
                if ($audioData) {
                    $tempFile = tempnam(sys_get_temp_dir(), 'audio');
                    file_put_contents($tempFile, $audioData);
                    $audio = uploadMedia(['tmp_name' => $tempFile, 'name' => 'recording.webm'], 'audio', $deckId);
                    unlink($tempFile);
                }
            }
        }

 
 
 
                
                if (addCard($deckId, $_POST['front'] ?? '', $_POST['back'] ?? '', $image, $audio)) {
                    header('Location: index.php?page=deck&id=' . urlencode($deckId));
                    exit;
                } else {
                    // Clean up uploaded files if card creation failed
                    if ($image) deleteMedia($image, $deckId);
                    if ($audio) deleteMedia($audio, $deckId);
                    $error = 'Failed to add card. Check permissions.';
                }
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
            
            if ($currentCard && checkDeckAccess($deckId, true)) {
                $image = $currentCard['image'] ?? '';
                $audio = $currentCard['audio'] ?? '';
                
                if (isset($_POST['delete_image']) && $_POST['delete_image'] === '1') {
                    deleteMedia($image, $deckId);
                    $image = '';
         } elseif (!empty($_FILES['image']['tmp_name'])) {
    $newImage = uploadMedia($_FILES['image'], 'image', $deckId);
    if ($newImage) {
        deleteMedia($image, $deckId);
        $image = $newImage;
    }
}

if (isset($_POST['deleteaudio']) && $_POST['deleteaudio'] == '1') {
    deleteMedia($audio, $deckId);
    $audio = '';
} elseif (!empty($_FILES['audio']['tmp_name'])) {
    $newAudio = uploadMedia($_FILES['audio'], 'audio', $deckId);
                    if ($newAudio) {
                        deleteMedia($audio, $deckId);
                        $audio = $newAudio;
                    }
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
    <title>Flashcard Learner</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>📚 Flashcard Learner</h1>
            <?php if (isLoggedIn()): ?>
                <div class="user-info">
                    <span>Welcome, <?= htmlspecialchars($_SESSION['user']) ?></span>
                    <form method="post" style="display:inline;">
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

        <?php if (isLoggedIn()): ?>
            <?php
            $page = $_GET['page'] ?? 'home';
            $deckId = $_GET['id'] ?? '';
            ?>

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
                                    <?php if (!$deck['isOwner']): ?>
                                        <p class="info-text" style="font-size: 0.85em; color: #6c757d;">
                                            👤 Owner: <?= htmlspecialchars($deck['owner']) ?>
                                        </p>
                                    <?php endif; ?>
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
                                        <a href="?page=deck&id=<?= urlencode($deck['id']) ?>" class="btn btn-small">Open</a>
                                        <a href="?page=study&id=<?= urlencode($deck['id']) ?>" class="btn btn-small btn-primary">Study</a>
                                        <?php if ($deck['isOwner']): ?>
                                            <button onclick="editDeck('<?= htmlspecialchars($deck['id'], ENT_QUOTES) ?>', '<?= htmlspecialchars($deck['name'], ENT_QUOTES) ?>')" class="btn btn-small">Edit</button>
                                            <button onclick="deleteDeck('<?= htmlspecialchars($deck['id'], ENT_QUOTES) ?>')" class="btn btn-small btn-danger">Delete</button>
                                        <?php endif; ?>
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
                if (!isset($decks[$deckId]) || !checkDeckAccess($deckId, false)) {
                    echo '<div class="content"><p class="error">Deck not found or access denied.</p></div>';
                } else {
                    $deck = $decks[$deckId];
                    $cards = getCards($deckId);
                    $progress = getProgress($deckId);
                    $isOwner = $deck['isOwner'];
                ?>
                    <div class="content">
                        <div class="breadcrumb">
                            <a href="index.php">← Back to Decks</a>
                        </div>
                        
                        <div class="section-header">
                            <div>
                                <h2><?= htmlspecialchars($deck['name']) ?></h2>
                                <?php if (!$isOwner): ?>
                                    <p class="info-text" style="font-size: 0.9em;">
                                        👤 Deck by: <?= htmlspecialchars($deck['owner']) ?>
                                    </p>
                                <?php endif; ?>
                                <div class="deck-stats-inline">
                                    <span>Total: <?= (int)$deck['stats']['total'] ?></span>
                                    <span class="known">✓ Known: <?= (int)$deck['stats']['known'] ?></span>
                                    <span class="unknown">✗ Unknown: <?= (int)$deck['stats']['unknown'] ?></span>
                                    <span>Not Reviewed: <?= (int)$deck['stats']['notReviewed'] ?></span>
                                </div>
                            </div>
                            <div>
                                <a href="?page=study&id=<?= urlencode($deckId) ?>" class="btn btn-primary">Study Deck</a>
                                <?php if ($isOwner): ?>
                                    <button onclick="showModal('addCardModal')" class="btn">+ Add Card</button>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <div class="cards-list">
                            <?php if (empty($cards)): ?>
                                <p class="empty-state">No cards yet. <?= $isOwner ? 'Add your first card!' : '' ?></p>
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
                                                <strong>Front:</strong> <?= nl2br(htmlspecialchars($card['front'])) ?>
                                            </div>
                                            <div class="card-side">
                                                <strong>Back:</strong> <?= nl2br(htmlspecialchars($card['back'])) ?>
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
                                        <?php if ($isOwner): ?>
                                            <div class="card-actions">
                                                <button onclick='editCard(<?= json_encode($card, JSON_HEX_APOS | JSON_HEX_QUOT) ?>, <?= json_encode($deckId, JSON_HEX_APOS | JSON_HEX_QUOT) ?>)' class="btn btn-small">Edit</button>
                                                <button onclick="deleteCard(<?= json_encode($deckId, JSON_HEX_APOS | JSON_HEX_QUOT) ?>, <?= json_encode($card['id'], JSON_HEX_APOS | JSON_HEX_QUOT) ?>)" class="btn btn-small btn-danger">Delete</button>
                                            </div>
                                        <?php endif; ?>
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
                if (!isset($decks[$deckId]) || !checkDeckAccess($deckId, false)) {
                    echo '<div class="content"><p class="error">Deck not found or access denied.</p></div>';
                } else {
                    $deck = $decks[$deckId];
                    $cards = getCards($deckId);
                    $progress = getProgress($deckId);
                    if (empty($cards)) {
                        echo '<div class="content"><p class="empty-state">No cards to study.</p></div>';
                    } else {
                ?>
                    <div class="content">
                        <div class="breadcrumb">
                            <a href="?page=deck&id=<?= urlencode($deckId) ?>">← Back to Deck</a>
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
                                    <div class="flip-hint">Click to flip</div>
                                </div>
                                <div class="flashcard-back">
                                    <div class="card-text" id="backText"></div>
                                    <div id="backMedia"></div>
                                    <div class="flip-hint">Click to flip back</div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="study-actions">
                            <button onclick="markCard('unknown')" class="btn btn-danger btn-large">✗ Don't Know</button>
                            <button onclick="nextCard()" class="btn btn-large">⏭️ Skip</button>
                            <button onclick="markCard('known')" class="btn btn-success btn-large">✓ I Know This</button>
                        </div>
                        
                        <div class="study-controls">
                            <button onclick="toggleStudyMode()" class="btn" id="studyModeBtn">Show Native on Front</button>
                            <button onclick="shuffleCards()" class="btn">🔀 Shuffle</button>
                            <button onclick="toggleUnknownOnly()" class="btn" id="unknownBtn">Review Unknown Only</button>
                            <button onclick="resetProgress()" class="btn btn-danger">Reset All Progress</button>
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
                            let isReversed = false;

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
                                const frontText = isReversed ? card.back : card.front;
                                const backText = isReversed ? card.front : card.back;
                                
                                document.getElementById('frontText').innerHTML = frontText.replace(/\n/g, '<br>');
                                document.getElementById('backText').innerHTML = backText.replace(/\n/g, '<br>');
                                
                                let frontMediaHtml = '';
                                let backMediaHtml = '';

                                if (card.image) {
                                    const imageUrl = 'index.php?media=' + encodeURIComponent(card.image);
                                    frontMediaHtml += `<img src="${imageUrl}" alt="Card image">`;
                                    backMediaHtml += `<img src="${imageUrl}" alt="Card image">`;
                                }

                                if (card.audio) {
                                    const audioUrl = 'index.php?media=' + encodeURIComponent(card.audio);
                                    frontMediaHtml += `<audio controls src="${audioUrl}"></audio>`;
                                    backMediaHtml += `<audio controls src="${audioUrl}"></audio>`;
                                }

                                document.getElementById('frontMedia').innerHTML = frontMediaHtml;
                                document.getElementById('backMedia').innerHTML = backMediaHtml;
                                
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
                                
                                if (status === 'known') {
                                    knownCards.add(cardId);
                                    unknownCards.delete(cardId);
                                } else if (status === 'unknown') {
                                    unknownCards.add(cardId);
                                    knownCards.delete(cardId);
                                }
                                
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

                            function toggleStudyMode() {
                                isReversed = !isReversed;
                                const btn = document.getElementById('studyModeBtn');
                                if (isReversed) {
                                    btn.textContent = 'Show Foreign on Front';
                                } else {
                                    btn.textContent = 'Show Native on Front';
                                }
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
                    </div>
                <?php
                    }
                }
                ?>
            <?php endif; ?>
        <?php else: ?>
            <!-- Login/Register Page -->
            <div class="content">
                <div class="auth-container">
                    <div class="auth-box">
                        <h2>Login</h2>
                        <form method="post">
                            <input type="hidden" name="action" value="login">
                            <input type="text" name="username" placeholder="Username" required maxlength="50" autocomplete="username">
                            <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
                            <button type="submit" class="btn">Login</button>
                        </form>
                    </div>
                    <div class="auth-box">
                        <h2>Register</h2>
                        <?php if (ALLOW_REGISTRATION): ?>
                            <form method="post">
                                <input type="hidden" name="action" value="register">
                                <input type="text" name="username" placeholder="Username (3-50 chars)" required maxlength="50" autocomplete="username">
                                <input type="password" name="password" placeholder="Password (min 8 chars)" required autocomplete="new-password">
                                <button type="submit" class="btn">Register</button>
                            </form>
                        <?php else: ?>
                            <p class="info-text">Public registration is currently disabled. Please contact the administrator to create an account.</p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
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
            <input type="text" name="deck_name" id="editDeckName" placeholder="Deck Name" required maxlength="200">
            <button type="submit" class="btn">Save Changes</button>
        </form>
    </div>
</div>

<div id="addCardModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeModal('addCardModal')">&times;</span>
        <h2>Add New Card</h2>
        <form method="post" enctype="multipart/form-data" id="addCardForm">
            <input type="hidden" name="action" value="add_card">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="deck_id" value="<?= htmlspecialchars($deckId) ?>">
            <label for="addCardFront">Front (Foreign Language):</label>
            <textarea name="front" id="addCardFront" required maxlength="1000" rows="4"></textarea>
            <label for="addCardBack">Back (Native Language):</label>
            <textarea name="back" id="addCardBack" required maxlength="1000" rows="4"></textarea>
            
            <label>Image (JPG, PNG, GIF, WebP - max 5MB):</label>
            <input type="file" name="image" accept=".jpg,.jpeg,.png,.gif,.webp">
            
            <label>Audio:</label>
            <div class="audio-options">
                <div class="audio-recorder" id="addCardRecorder">
                    <button type="button" class="btn btn-small" onclick="startRecording('add')">🎤 Record Audio</button>
                    <div id="addRecordingControls" style="display: none; margin-top: 10px;">
                        <div class="recording-status">
                            <span class="recording-indicator">🔴 Recording...</span>
                            <span id="addRecordingTime">0:00</span>
                        </div>
                        <button type="button" class="btn btn-small btn-danger" onclick="stopRecording('add')">⏹️ Stop</button>
                    </div>
                    <div id="addRecordedAudio" style="margin-top: 10px;"></div>
                </div>
                <div style="text-align: center; margin: 10px 0; color: #6c757d;">— OR —</div>
                <input type="file" name="audio" id="addAudioFile" accept=".mp3,.wav,.ogg,.m4a">
            </div>
            
            <button type="submit" class="btn">Add Card</button>
        </form>
    </div>
</div>

<div id="editCardModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeModal('editCardModal')">&times;</span>
        <h2>Edit Card</h2>
        <form method="post" enctype="multipart/form-data" id="editCardForm">
            <input type="hidden" name="action" value="edit_card">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="deck_id" id="editCardDeckId">
            <input type="hidden" name="card_id" id="editCardId">
            <label for="editCardFront">Front (Foreign Language):</label>
            <textarea name="front" id="editCardFront" required maxlength="1000" rows="4"></textarea>
            <label for="editCardBack">Back (Native Language):</label>
            <textarea name="back" id="editCardBack" required maxlength="1000" rows="4"></textarea>
            
            <div id="currentImage"></div>
            <label>New Image (JPG, PNG, GIF, WebP - max 5MB):</label>
            <input type="file" name="image" accept=".jpg,.jpeg,.png,.gif,.webp">
            
            <div id="currentAudio"></div>
            <label>New Audio:</label>
            <div class="audio-options">
                <div class="audio-recorder" id="editCardRecorder">
                    <button type="button" class="btn btn-small" onclick="startRecording('edit')">🎤 Record Audio</button>
                    <div id="editRecordingControls" style="display: none; margin-top: 10px;">
                        <div class="recording-status">
                            <span class="recording-indicator">🔴 Recording...</span>
                            <span id="editRecordingTime">0:00</span>
                        </div>
                        <button type="button" class="btn btn-small btn-danger" onclick="stopRecording('edit')">⏹️ Stop</button>
                    </div>
                    <div id="editRecordedAudio" style="margin-top: 10px;"></div>
                </div>
                <div style="text-align: center; margin: 10px 0; color: #6c757d;">— OR —</div>
                <input type="file" name="audio" id="editAudioFile" accept=".mp3,.wav,.ogg,.m4a">
            </div>
            
            <button type="submit" class="btn">Save Changes</button>
        </form>
    </div>
</div>

<style>
.audio-options {
    background: #f8f9fa;
    padding: 15px;
    border-radius: 8px;
    margin-bottom: 15px;
}

.audio-recorder {
    text-align: center;
}

.recording-status {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 15px;
    margin-bottom: 10px;
    font-weight: 600;
}

.recording-indicator {
    color: #dc3545;
    animation: pulse 1.5s infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.recorded-preview {
    background: white;
    padding: 15px;
    border-radius: 8px;
    margin-top: 10px;
    border: 2px solid #28a745;
}

.recorded-preview audio {
    width: 100%;
    margin-top: 10px;
}

.recorded-preview .controls {
    display: flex;
    gap: 10px;
    margin-top: 10px;
    justify-content: center;
}
</style>

<script>
const csrfToken = <?= json_encode($csrfToken) ?>;

// Audio Recording Variables
let mediaRecorder = null;
let audioChunks = [];
let recordingTimer = null;
let recordingStartTime = 0;
let currentRecordingMode = null;
let recordedBlob = null;

async function startRecording(mode) {
    currentRecordingMode = mode;
    audioChunks = [];  // FIX: Changed from "audioChunks recordedBlob null"
    recordedBlob = null;
    
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorder = new MediaRecorder(stream);
        
        mediaRecorder.ondataavailable = (event) => {
            audioChunks.push(event.data);
        };
        
        mediaRecorder.onstop = () => {
            const blob = new Blob(audioChunks, { type: 'audio/webm' });
            recordedBlob = blob;
            displayRecordedAudio(mode, blob);
            // Stop all tracks to release microphone
            stream.getTracks().forEach(track => track.stop());
        };
        
        mediaRecorder.start();
        
        // Show recording controls
        document.getElementById(`${mode}RecordingControls`).style.display = 'block';
        document.querySelector(`#${mode}CardRecorder .btn:first-child`).style.display = 'none';
        
        // Start timer
        recordingStartTime = Date.now();
        recordingTimer = setInterval(() => {
            const elapsed = Math.floor((Date.now() - recordingStartTime) / 1000);
            const minutes = Math.floor(elapsed / 60);
            const seconds = elapsed % 60;
            document.getElementById(`${mode}RecordingTime`).textContent = 
                `${minutes}:${seconds.toString().padStart(2, '0')}`;
        }, 1000);
    } catch (error) {
        alert('Could not access microphone. Please allow microphone access and try again.');
        console.error('Error accessing microphone:', error);
    }
}

function stopRecording(mode) {
    if (mediaRecorder && mediaRecorder.state !== 'inactive') {
        mediaRecorder.stop();
    }
    
    // Clear timer
    if (recordingTimer) {
        clearInterval(recordingTimer);
        recordingTimer = null;
    }
    
    // Hide recording controls
    document.getElementById(`${mode}RecordingControls`).style.display = 'none';
    document.querySelector(`#${mode}CardRecorder .btn:first-child`).style.display = 'inline-block';
}

function displayRecordedAudio(mode, blob) {
    const url = URL.createObjectURL(blob);
    const container = document.getElementById(`${mode}RecordedAudio`);
    
    container.innerHTML = `
        <div class="recorded-preview">
            <strong>✓ Audio Recorded</strong>
            <audio controls src="${url}"></audio>
            <div class="controls">
                <button type="button" class="btn btn-small btn-rerecord">🔄 Re-record</button>
                <button type="button" class="btn btn-small btn-danger btn-delete-rec">🗑️ Delete</button>
            </div>
        </div>
    `;
    
    // Add event listeners
    container.querySelector('.btn-rerecord').onclick = () => startRecording(mode);
    container.querySelector('.btn-delete-rec').onclick = () => deleteRecording(mode);
    
    // Disable file input when recording is present
    const fileInput = document.getElementById(`${mode}AudioFile`);
    if (fileInput) {
        fileInput.disabled = true;
        fileInput.style.opacity = '0.5';
    }
}


    
function deleteRecording(mode) {
    recordedBlob = null;
    document.getElementById(`${mode}RecordedAudio`).innerHTML = '';
    
    // Re-enable file input
    const fileInput = document.getElementById(`${mode}AudioFile`);
    if (fileInput) {
        fileInput.disabled = false;
        fileInput.style.opacity = '1';
    }
}

// Handle form submission with recorded audio
document.addEventListener('DOMContentLoaded', function() {
    const addForm = document.getElementById('addCardForm');
    const editForm = document.getElementById('editCardForm');
    
    if (addForm) {
        addForm.addEventListener('submit', function(e) {
            if (recordedBlob && currentRecordingMode === 'add') {
                e.preventDefault();
                submitFormWithRecording(addForm, recordedBlob);
            }
        });
    }
    
    if (editForm) {
        editForm.addEventListener('submit', function(e) {
            if (recordedBlob && currentRecordingMode === 'edit') {
                e.preventDefault();
                submitFormWithRecording(editForm, recordedBlob);
            }
        });
    }
});

function submitFormWithRecording(form, blob) {
    const formData = new FormData(form);
    // Remove the file input and add recorded audio as blob
    formData.delete('audio');
    formData.append('audio', blob, 'recording.webm');
    
    // Submit via fetch - use getAttribute to avoid conflict with input name="action"
    fetch(form.getAttribute('action') || 'index.php', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.ok) {
            window.location.reload();
        } else {
            alert('Failed to save card. Please try again.');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred. Please try again.');
    });
}

// Clean up when modal closes
function closeModal(id) {
    document.getElementById(id).style.display = 'none';
    
    // Stop any ongoing recording
    if (mediaRecorder && mediaRecorder.state !== 'inactive') {
        stopRecording(currentRecordingMode);
    }
    
    // Clear recordings
    if (id === 'addCardModal') {
        deleteRecording('add');
    } else if (id === 'editCardModal') {
        deleteRecording('edit');
    }
}

function showModal(id) {
    document.getElementById(id).style.display = 'block';
}

function editDeck(id, name) {
    document.getElementById('editDeckId').value = id;
    document.getElementById('editDeckName').value = name;
    showModal('editDeckModal');
}

function deleteDeck(id) {
    if (confirm('Delete this deck and all its cards? This cannot be undone.')) {
        const form = document.createElement('form');
        form.method = 'post';
        form.innerHTML = `
            <input type="hidden" name="action" value="delete_deck">
            <input type="hidden" name="deck_id" value="${id}">
            <input type="hidden" name="csrf_token" value="${csrfToken}">
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
    
    const currentImageDiv = document.getElementById('currentImage');
    const currentAudioDiv = document.getElementById('currentAudio');
    
    currentImageDiv.innerHTML = '';
    currentAudioDiv.innerHTML = '';
    
    if (card.image) {
        currentImageDiv.innerHTML = `
            <div class="current-media">
                <p>Current Image:</p>
                <img src="index.php?media=${encodeURIComponent(card.image)}" alt="Current image" style="max-width: 100%; max-height: 150px; border-radius: 8px;">
                <label>
                    <input type="checkbox" name="delete_image" value="1"> Delete current image
                </label>
            </div>
        `;
    }
    
    if (card.audio) {
        currentAudioDiv.innerHTML = `
            <div class="current-media">
                <p>Current Audio:</p>
                <audio controls src="index.php?media=${encodeURIComponent(card.audio)}" style="width: 100%;"></audio>
                <label>
                    <input type="checkbox" name="delete_audio" value="1"> Delete current audio
                </label>
            </div>
        `;
    }
    
    // Clear any previous recordings
    deleteRecording('edit');
    
    showModal('editCardModal');
}

function deleteCard(deckId, cardId) {
    if (confirm('Delete this card? This cannot be undone.')) {
        const form = document.createElement('form');
        form.method = 'post';
        form.innerHTML = `
            <input type="hidden" name="action" value="delete_card">
            <input type="hidden" name="deck_id" value="${deckId}">
            <input type="hidden" name="card_id" value="${cardId}">
            <input type="hidden" name="csrf_token" value="${csrfToken}">
        `;
        document.body.appendChild(form);
        form.submit();
    }
}

// Close modal if clicked outside
window.onclick = function(event) {
    const modals = document.getElementsByClassName('modal');
    for (let i = 0; i < modals.length; i++) {
        if (event.target == modals[i]) {
            closeModal(modals[i].id);
        }
    }
}
</script>


</body>
</html>                           
                                
                                
                                
                                
