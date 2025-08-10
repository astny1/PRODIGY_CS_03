#  Password Complexity Checker - Python Edition

A **secure, advanced password complexity checker** built in Python with both GUI and command-line interfaces. This version offers superior security compared to web-based solutions by running locally and providing comprehensive cryptographic analysis.

## **Why Python for Security?**

### **Advantages over HTML/JavaScript:**
- ✅ **Local Processing**: No data leaves your machine
- ✅ **Cryptographic Security**: Uses Python's `secrets` module for true randomness
- ✅ **Advanced Analysis**: Entropy calculation, pattern detection, breach checking
- ✅ **No Network Dependencies**: Works offline, no external API calls
- ✅ **Memory Safety**: Better memory management and security
- ✅ **Extensible**: Easy to add custom security rules and databases

##  **Features**

### **Core Security Analysis**
- **Real-time Password Assessment**: Instant analysis as you type
- **8 Security Criteria**: Comprehensive validation including entropy
- **Pattern Detection**: Identifies common patterns and sequences
- **Breach Database Check**: Compares against known compromised passwords
- **Entropy Calculation**: Mathematical randomness measurement
- **Character Analysis**: Detailed breakdown of character types

### **Advanced Security Features**
- **Cryptographically Secure Generation**: Uses `secrets` module
- **SHA-256 Hashing**: Secure hash generation for analysis
- **Thread-Safe Processing**: Non-blocking UI with background analysis
- **Password History**: Secure logging for analysis (hashed only)
- **Multiple Interfaces**: GUI, CLI, and programmatic access

### **Security Criteria**
1. **Length**: Minimum 8 characters (12+ recommended)
2. **Uppercase Letters**: At least one A-Z character
3. **Lowercase Letters**: At least one a-z character
4. **Numbers**: At least one 0-9 digit
5. **Special Characters**: At least one special character
6. **Not Common**: Avoids known common passwords
7. **No Patterns**: Detects obvious sequences and repetitions
8. **High Entropy**: Ensures sufficient randomness

##  **Installation**

### **Prerequisites**
- Python 3.7+ (recommended: Python 3.9+)
- No external dependencies required!

### **Quick Start**
```bash
# Clone or download the files
# Navigate to the project directory

# Run GUI version
python password_checker.py

# Run CLI version
python password_checker_cli.py

# Generate a secure password
python password_checker_cli.py -g

# Check a specific password
python password_checker_cli.py -p "MyPassword123!"
```

##  **Usage**

### **GUI Version (`password_checker.py`)**
```bash
python password_checker.py
```

**Features:**
- Modern dark theme interface
- Real-time password analysis
- Visual strength meter
- Interactive criteria checklist
- Advanced analysis panel
- Secure password generation

### **Command Line Version (`password_checker_cli.py`)**

#### **Interactive Mode**
```bash
python password_checker_cli.py
```
- Secure password input (hidden)
- Real-time analysis
- Type 'quit' to exit
- Type 'generate' for secure password

#### **Direct Password Check**
```bash
python password_checker_cli.py -p "MyPassword123!"
```

#### **Generate Secure Password**
```bash
# Generate 16-character password (default)
python password_checker_cli.py -g

# Generate custom length password
python password_checker_cli.py -g -l 20
```

#### **Verbose Analysis**
```bash
python password_checker_cli.py -v -p "test123"
```

#### **JSON Output**
```bash
python password_checker_cli.py -j -p "MyPassword123!"
```

#### **Save Results to File**
```bash
python password_checker_cli.py -p "MyPassword123!" -f results.json
```

##  **Command Line Options**

```bash
python password_checker_cli.py [OPTIONS]

Options:
  -p, --password TEXT    Password to analyze
  -g, --generate         Generate a secure password
  -l, --length INTEGER   Length for generated password (default: 16)
  -v, --verbose          Verbose output with additional details
  -j, --json             Output results in JSON format
  -f, --file TEXT        Save results to file
  -h, --help             Show help message
```

##  **Security Analysis Algorithm**

### **Scoring System (0-100 points)**

**Base Criteria (40 points)**
- Length, Uppercase, Lowercase, Number, Special: 8 points each

**Advanced Criteria (30 points)**
- Not Common Password: 10 points
- No Patterns: 10 points
- High Entropy: 10 points

**Length Bonus (20 points)**
- 12+ characters: 20 points
- 10+ characters: 15 points
- 8+ characters: 10 points

**Complexity Bonus (10 points)**
- 6+ criteria met: 10 points
- 4+ criteria met: 5 points

### **Strength Levels**
- **Strong (80-100)**: Excellent security
- **Good (60-79)**: Good security
- **Fair (40-59)**: Acceptable but improvable
- **Weak (0-39)**: Needs improvement

##  **Security Features**

### **Cryptographic Security**
- Uses `secrets` module for cryptographically secure random generation
- SHA-256 hashing for password analysis
- No plaintext password storage
- Secure memory handling

### **Privacy Protection**
- **Local Processing**: All analysis happens on your machine
- **No Network Calls**: Works completely offline
- **No Data Collection**: No telemetry or logging
- **Secure Input**: Hidden password input in CLI

### **Advanced Detection**
- **Pattern Recognition**: Detects sequences like "123", "abc", "qwerty"
- **Common Password Check**: Compares against known weak passwords
- **Entropy Analysis**: Mathematical randomness measurement
- **Character Distribution**: Analyzes character type balance

##  **Example Usage**

### **GUI Example**
```python
# Run the GUI application
python password_checker.py
```
- Enter password in the input field
- Watch real-time analysis
- View strength meter and criteria
- Generate secure passwords with one click

### **CLI Examples**
```bash
# Interactive mode
python password_checker_cli.py
# Enter: MySecurePassword123!
# Result: Strong (85/100)

# Generate password
python password_checker_cli.py -g -l 20
# Result: K9#mN$pQ2@vX7&hL5!jR

# Check specific password
python password_checker_cli.py -p "password123"
# Result: Weak (25/100) - Common password detected

# Verbose analysis
python password_checker_cli.py -v -p "MyComplexP@ssw0rd!"
# Result: Detailed analysis with hash and timestamp
```

##  **Programmatic Usage**

```python
from password_checker_cli import PasswordAnalyzer

# Create analyzer
analyzer = PasswordAnalyzer()

# Analyze password
analysis = analyzer.analyze_password("MyPassword123!")

# Access results
print(f"Strength: {analysis['strength_level']}")
print(f"Score: {analysis['strength_score']}/100")
print(f"Entropy: {analysis['entropy']:.2f}")

# Generate secure password
secure_password = analyzer.generate_secure_password(16)
print(f"Generated: {secure_password}")
```

##  **Security Best Practices**

### **For Users**
- Use the CLI version for maximum security
- Never share passwords in plain text
- Use generated passwords for critical accounts
- Regularly update passwords
- Use different passwords for different services

### **For Developers**
- Run analysis locally, never send passwords over network
- Use secure random generation (`secrets` module)
- Hash passwords before any storage
- Implement rate limiting for password checks
- Log security events (without passwords)

##  **Troubleshooting**

### **Common Issues**
```bash
# GUI not working
# Solution: Ensure tkinter is installed
python -c "import tkinter; print('tkinter available')"

# Permission denied
# Solution: Make executable
chmod +x password_checker_cli.py

# Python version issues
# Solution: Use Python 3.7+
python --version
```

## **Performance**

- **Analysis Speed**: < 1ms for typical passwords
- **Memory Usage**: < 10MB for GUI version
- **CPU Usage**: Minimal background processing
- **Startup Time**: < 2 seconds

##  **License**

This project is open source and available under the MIT License.

---

** Built with security-first principles in Python**
