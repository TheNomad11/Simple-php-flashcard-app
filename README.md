# 📚 Simple php Flashcard App (vibe coded with Claude Sonnet 4.5)

A simple, self-contained PHP flashcard application for language learning with support for text, images, and audio. Perfect for creating personalized vocabulary decks and tracking learning progress.

## ✨ Features

- **Create custom decks** for different topics or languages
- **Add multimedia flashcards** with text, images, and audio support
- **Interactive study mode** with flip animations
- **Progress tracking** for known/unknown cards
- **Shuffle cards** for varied learning
- **Review unknown cards only** for focused study
- **Responsive design** that works on desktop and mobile
- **User authentication** with secure password hashing
- **Single-file media management** with automatic cleanup
- **Print-friendly layouts** for physical study cards

## 📋 Requirements

- PHP 7.4 or higher
- Web server with PHP support (Apache, Nginx, etc.)
- File system write permissions for data storage

## 🚀 Installation

1. **Download** the application files to your web server
2. **Ensure the `data/` directory is writable** by the web server:
   ```bash
   mkdir data
   chmod 755 data
   ```
3. **Configure user registration** in `index.php`:
   ```php
   define('ALLOW_REGISTRATION', true);  // Set to false after creating accounts
   ```
4. **Create your first user account** by visiting the registration page
5. **(Optional) Use `register_user.php`** for manual account creation when registration is disabled

## 🛠️ Usage

### Creating Accounts

1. Set `ALLOW_REGISTRATION` to `true` in `index.php`
2. Visit the app in your browser and register
3. For additional security, after creating accounts:
   - Set `ALLOW_REGISTRATION` to `false`
   - Delete `register_user.php` if used

### Creating Decks

1. Click **"➕ New Deck"** on the main page
2. Enter a descriptive name (e.g., "Spanish Verbs", "Medical Terms")
3. Click **"Create"**

### Adding Flashcards

1. Navigate to your deck
2. Click **"➕ Add Card"**
3. Enter the front and back text (e.g., word and translation)
4. Optionally upload:
   - **Images** (JPG, PNG, GIF, WebP - max 5MB)
   - **Audio** (MP3, WAV, OGG, M4A - max 5MB)
5. Click **"Add Card"**

### Studying

1. Click **"Study"** on any deck
2. Click cards to flip them
3. Mark cards as:
   - **✓ I Know This** (moves to known)
   - **❌ Don't Know** (moves to unknown)
   - **⏭️ Skip** (no status change)
4. Use study controls:
   - **🔀 Shuffle** to randomize card order
   - **Review Unknown Only** to focus on difficult cards
   - **Reset All Progress** to start over

## 🔐 Security Features

- Password hashing with `password_hash()`
- CSRF protection tokens
- File upload validation (type, size, MIME)
- Secure session management
- Input sanitization and validation

## 📁 File Structure

```
flashcard-app/
├── index.php          # Main application file
├── styles.css         # All styling
├── register_user.php  # Manual user registration (delete after use)
├── data/              # User data directory (must be writable)
│   ├── users.txt      # User accounts
│   ├── media/         # Uploaded images/audio
│   └── [deck files]   # Individual deck data
└── README.md          # This file
```

## 🎨 Customization

### Styling

Modify `styles.css` to change:
- Color schemes
- Card dimensions
- Animations
- Responsive breakpoints

### Configuration

Adjust settings in `index.php`:
```php
define('MAX_FILE_SIZE', 5 * 1024 * 1024);  // 5MB file limit
define('ALLOW_REGISTRATION', true);         // User registration
```

## 📱 Responsive Design

The app is fully responsive and works on:
- **Desktop browsers** (Chrome, Firefox, Safari, Edge)
- **Tablets** (768px and above)
- **Mobile phones** (480px and above)
- **Print media** (cards can be printed for physical study)

## 🗑️ Data Management

- Deleting a deck automatically removes all associated cards and media
- Deleting a card automatically removes its media files
- User progress is automatically saved during study sessions

## ⚠️ Important Security Notes

1. **Delete `register_user.php`** after creating accounts
2. **Set proper file permissions** on the `data/` directory
3. **Use HTTPS** in production environments
4. **Change default passwords** if using manual registration


## 📄 License

This project is open source and available under the [MIT License](LICENSE).

