<?php
/**
 * Manual User Registration Script
 * 
 * Use this script to manually create user accounts when ALLOW_REGISTRATION is set to false.
 * 
 * SECURITY WARNING: Delete this file after creating all necessary accounts!
 * 
 * Usage:
 *   1. Upload this file to the same directory as index.php
 *   2. Access via browser: https://yourdomain.com/register_user.php
 *   3. Create accounts
 *   4. DELETE this file immediately after use!
 */

// Configuration
define('DATA_DIR', __DIR__ . '/data');
define('USERS_FILE', DATA_DIR . '/users.txt');

// Simple password protection for this script
// CHANGE THIS PASSWORD before using!
define('ADMIN_PASSWORD', 'change-this-secret-password-123');

$message = '';
$error = '';
$authenticated = false;

// Check authentication
session_start();
if (isset($_POST['admin_auth'])) {
    if ($_POST['admin_password'] === ADMIN_PASSWORD) {
        $_SESSION['admin_authenticated'] = true;
        $authenticated = true;
    } else {
        $error = 'Invalid admin password!';
    }
}

if (isset($_SESSION['admin_authenticated']) && $_SESSION['admin_authenticated'] === true) {
    $authenticated = true;
}

// Handle user creation
if ($authenticated && isset($_POST['create_user'])) {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    
    // Validation
    if (strlen($username) < 3 || strlen($username) > 50) {
        $error = 'Username must be 3-50 characters.';
    } elseif (!preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
        $error = 'Username can only contain letters, numbers, underscore, and hyphen.';
    } elseif (strlen($password) < 8) {
        $error = 'Password must be at least 8 characters.';
    } else {
        // Check if user exists
        $users = file_exists(USERS_FILE) ? file(USERS_FILE, FILE_IGNORE_NEW_LINES) : [];
        $userExists = false;
        
        foreach ($users as $user) {
            if (empty($user)) continue;
            list($u, $h) = explode(':', $user, 2);
            if ($u === $username) {
                $userExists = true;
                break;
            }
        }
        
        if ($userExists) {
            $error = "User '$username' already exists!";
        } else {
            // Create user
            if (!is_dir(DATA_DIR)) {
                mkdir(DATA_DIR, 0755, true);
            }
            
            $hash = password_hash($password, PASSWORD_DEFAULT);
            file_put_contents(USERS_FILE, "$username:$hash\n", FILE_APPEND | LOCK_EX);
            chmod(USERS_FILE, 0644);
            
            $message = "✅ User '$username' created successfully!";
        }
    }
}

// List existing users
$existingUsers = [];
if ($authenticated && file_exists(USERS_FILE)) {
    $users = file(USERS_FILE, FILE_IGNORE_NEW_LINES);
    foreach ($users as $user) {
        if (empty($user)) continue;
        list($u, $h) = explode(':', $user, 2);
        $existingUsers[] = $u;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manual User Registration</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 600px;
            width: 100%;
            padding: 40px;
        }
        h1 {
            color: #667eea;
            margin-bottom: 10px;
        }
        .warning {
            background: #fff3cd;
            border: 2px solid #ffc107;
            color: #856404;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            font-weight: 600;
        }
        .message {
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            font-weight: 600;
        }
        .message.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .message.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 1em;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 12px 24px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        .btn:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        .btn-danger {
            background: #dc3545;
        }
        .btn-danger:hover {
            background: #c82333;
        }
        .user-list {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-top: 30px;
        }
        .user-list h2 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.3em;
        }
        .user-list ul {
            list-style: none;
        }
        .user-list li {
            padding: 10px;
            background: white;
            margin-bottom: 8px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .instructions {
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .instructions h3 {
            color: #2196F3;
            margin-bottom: 10px;
        }
        .instructions ol {
            margin-left: 20px;
        }
        .instructions li {
            margin-bottom: 8px;
        }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Manual User Registration</h1>
        
        <div class="warning">
            ⚠️ <strong>SECURITY WARNING:</strong> Delete this file (register_user.php) immediately after creating all necessary accounts!
        </div>

        <?php if (!$authenticated): ?>
            <!-- Admin Authentication -->
            <div class="instructions">
                <h3>First Time Setup:</h3>
                <ol>
                    <li>Open <code>register_user.php</code> in a text editor</li>
                    <li>Find line 19: <code>define('ADMIN_PASSWORD', '...');</code></li>
                    <li>Change the password to something secure</li>
                    <li>Save and refresh this page</li>
                </ol>
            </div>

            <?php if ($error): ?>
                <div class="message error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <form method="post">
                <div class="form-group">
                    <label>Admin Password:</label>
                    <input type="password" name="admin_password" required autofocus>
                </div>
                <button type="submit" name="admin_auth" class="btn">Authenticate</button>
            </form>

        <?php else: ?>
            <!-- User Creation Form -->
            <?php if ($message): ?>
                <div class="message success"><?= htmlspecialchars($message) ?></div>
            <?php endif; ?>
            
            <?php if ($error): ?>
                <div class="message error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>

            <form method="post">
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" name="username" placeholder="3-50 chars, alphanumeric only" required>
                    <small style="color: #6c757d;">Only letters, numbers, underscore, and hyphen allowed</small>
                </div>
                
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" placeholder="Minimum 8 characters" required>
                </div>
                
                <button type="submit" name="create_user" class="btn">Create User</button>
            </form>

            <?php if (!empty($existingUsers)): ?>
            <div class="user-list">
                <h2>📋 Existing Users (<?= count($existingUsers) ?>)</h2>
                <ul>
                    <?php foreach ($existingUsers as $user): ?>
                        <li>👤 <?= htmlspecialchars($user) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
            <?php endif; ?>

            <div class="instructions" style="margin-top: 30px;">
                <h3>✅ After Creating All Users:</h3>
                <ol>
                    <li><strong>DELETE this file:</strong> <code>rm register_user.php</code></li>
                    <li>Set registration to false in index.php: <code>define('ALLOW_REGISTRATION', false);</code></li>
                    <li>Users can now login at: <a href="index.php">index.php</a></li>
                </ol>
            </div>

            <form method="post" action="?delete=1" style="margin-top: 20px;" onsubmit="return confirm('Are you sure you want to delete this registration script?');">
                <button type="submit" class="btn btn-danger">🗑️ Delete This Script Now</button>
            </form>

            <?php
            // Handle script deletion
            if (isset($_GET['delete'])) {
                if (unlink(__FILE__)) {
                    echo '<div class="message success">✅ Script deleted successfully! Redirecting...</div>';
                    echo '<meta http-equiv="refresh" content="2;url=index.php">';
                } else {
                    echo '<div class="message error">❌ Could not delete script. Please delete manually.</div>';
                }
            }
            ?>
        <?php endif; ?>
    </div>
</body>
</html>
