import tkinter as tk
from tkinter import ttk, messagebox
import re
import secrets
import string
import hashlib
import json
from datetime import datetime
import threading
import time

class PasswordComplexityChecker:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Complexity Checker - Secure Edition")
        self.root.geometry("700x800")
        self.root.configure(bg='#2c3e50')
        
        # Security settings
        self.common_passwords = self.load_common_passwords()
        self.password_history = []
        self.max_history = 100
        
        self.setup_ui()
        self.setup_styles()
        
    def load_common_passwords(self):
        """Load common passwords from a file or use built-in list"""
        common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'sunshine', 'princess', 'qwerty123',
            'football', 'baseball', 'superman', 'batman', 'trustno1'
        ]
        return set(common_passwords)
    
    def setup_styles(self):
        """Configure modern styling for the application"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', 
                       font=('Arial', 16, 'bold'), 
                       foreground='#ecf0f1',
                       background='#2c3e50')
        
        style.configure('Info.TLabel',
                       font=('Arial', 10),
                       foreground='#bdc3c7',
                       background='#2c3e50')
        
        style.configure('Strength.TLabel',
                       font=('Arial', 12, 'bold'),
                       background='#2c3e50')
        
        style.configure('Custom.TFrame',
                       background='#34495e')
        
    def setup_ui(self):
        """Create the user interface"""
        # Main container
        main_frame = ttk.Frame(self.root, style='Custom.TFrame', padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, 
                               text="🔒 Password Complexity Checker", 
                               style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        subtitle_label = ttk.Label(main_frame,
                                  text="Advanced Security Analysis & Password Generation",
                                  style='Info.TLabel')
        subtitle_label.pack(pady=(0, 30))
        
        # Password input section
        self.create_password_input(main_frame)
        
        # Strength meter
        self.create_strength_meter(main_frame)
        
        # Criteria section
        self.create_criteria_section(main_frame)
        
        # Advanced analysis
        self.create_advanced_analysis(main_frame)
        
        # Buttons section
        self.create_buttons_section(main_frame)
        
        # Results section
        self.create_results_section(main_frame)
        
    def create_password_input(self, parent):
        """Create password input field with show/hide toggle"""
        input_frame = ttk.Frame(parent, style='Custom.TFrame')
        input_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Label
        input_label = ttk.Label(input_frame, 
                               text="Enter Password:", 
                               style='Info.TLabel')
        input_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Input field with show/hide
        input_container = ttk.Frame(input_frame)
        input_container.pack(fill=tk.X)
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(input_container, 
                                      textvariable=self.password_var,
                                      show="*",
                                      font=('Arial', 12),
                                      bg='#ecf0f1',
                                      fg='#2c3e50',
                                      relief=tk.FLAT,
                                      bd=10)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.show_password_var = tk.BooleanVar()
        self.show_checkbox = tk.Checkbutton(input_container,
                                           text="Show",
                                           variable=self.show_password_var,
                                           command=self.toggle_password_visibility,
                                           bg='#34495e',
                                           fg='#ecf0f1',
                                           selectcolor='#2c3e50',
                                           activebackground='#34495e',
                                           activeforeground='#ecf0f1')
        self.show_checkbox.pack(side=tk.RIGHT)
        
        # Bind events
        self.password_var.trace('w', self.on_password_change)
        
    def create_strength_meter(self, parent):
        """Create visual strength meter"""
        meter_frame = ttk.Frame(parent, style='Custom.TFrame')
        meter_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Strength label
        self.strength_label = ttk.Label(meter_frame,
                                       text="Password Strength: Enter a password",
                                       style='Strength.TLabel')
        self.strength_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Progress bar
        self.strength_bar = ttk.Progressbar(meter_frame,
                                           length=400,
                                           mode='determinate',
                                           style='Horizontal.TProgressbar')
        self.strength_bar.pack(fill=tk.X)
        
    def create_criteria_section(self, parent):
        """Create criteria checklist"""
        criteria_frame = ttk.Frame(parent, style='Custom.TFrame')
        criteria_frame.pack(fill=tk.X, pady=(0, 20))
        
        criteria_label = ttk.Label(criteria_frame,
                                  text="Security Criteria:",
                                  style='Info.TLabel')
        criteria_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Criteria variables
        self.criteria_vars = {}
        self.criteria_labels = {}
        
        criteria_list = [
            ('length', 'At least 8 characters long'),
            ('uppercase', 'Contains uppercase letter (A-Z)'),
            ('lowercase', 'Contains lowercase letter (a-z)'),
            ('number', 'Contains number (0-9)'),
            ('special', 'Contains special character (!@#$%^&*)'),
            ('not_common', 'Not a common password'),
            ('no_patterns', 'No obvious patterns'),
            ('entropy', 'High entropy (randomness)')
        ]
        
        for criterion, description in criteria_list:
            var = tk.BooleanVar()
            self.criteria_vars[criterion] = var
            
            label = ttk.Label(criteria_frame,
                             text=f"❌ {description}",
                             style='Info.TLabel')
            label.pack(anchor=tk.W, pady=2)
            self.criteria_labels[criterion] = label
            
    def create_advanced_analysis(self, parent):
        """Create advanced security analysis section"""
        analysis_frame = ttk.Frame(parent, style='Custom.TFrame')
        analysis_frame.pack(fill=tk.X, pady=(0, 20))
        
        analysis_label = ttk.Label(analysis_frame,
                                  text="Advanced Analysis:",
                                  style='Info.TLabel')
        analysis_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Analysis results
        self.analysis_text = tk.Text(analysis_frame,
                                    height=6,
                                    bg='#34495e',
                                    fg='#ecf0f1',
                                    font=('Consolas', 9),
                                    relief=tk.FLAT,
                                    bd=5)
        self.analysis_text.pack(fill=tk.X)
        
    def create_buttons_section(self, parent):
        """Create action buttons"""
        buttons_frame = ttk.Frame(parent, style='Custom.TFrame')
        buttons_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Generate password button
        self.generate_btn = tk.Button(buttons_frame,
                                     text="🔐 Generate Secure Password",
                                     command=self.generate_secure_password,
                                     bg='#27ae60',
                                     fg='white',
                                     font=('Arial', 11, 'bold'),
                                     relief=tk.FLAT,
                                     bd=10,
                                     cursor='hand2')
        self.generate_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Clear button
        self.clear_btn = tk.Button(buttons_frame,
                                  text="🗑️ Clear",
                                  command=self.clear_all,
                                  bg='#e74c3c',
                                  fg='white',
                                  font=('Arial', 11),
                                  relief=tk.FLAT,
                                  bd=10,
                                  cursor='hand2')
        self.clear_btn.pack(side=tk.LEFT)
        
    def create_results_section(self, parent):
        """Create results and recommendations section"""
        results_frame = ttk.Frame(parent, style='Custom.TFrame')
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        results_label = ttk.Label(results_frame,
                                 text="Security Recommendations:",
                                 style='Info.TLabel')
        results_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Results text
        self.results_text = tk.Text(results_frame,
                                   bg='#34495e',
                                   fg='#ecf0f1',
                                   font=('Arial', 10),
                                   relief=tk.FLAT,
                                   bd=5,
                                   wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
            
    def on_password_change(self, *args):
        """Handle password input changes"""
        password = self.password_var.get()
        
        if not password:
            self.reset_analysis()
            return
            
        # Run analysis in a separate thread to avoid UI freezing
        threading.Thread(target=self.analyze_password, args=(password,), daemon=True).start()
        
    def analyze_password(self, password):
        """Comprehensive password analysis"""
        # Basic criteria checks
        checks = {
            'length': len(password) >= 8,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'number': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password)),
            'not_common': password.lower() not in self.common_passwords,
            'no_patterns': not self.has_obvious_patterns(password),
            'entropy': self.calculate_entropy(password) > 3.0
        }
        
        # Calculate strength score
        strength_score = self.calculate_strength_score(checks, password)
        
        # Update UI in main thread
        self.root.after(0, lambda: self.update_ui(checks, strength_score, password))
        
    def has_obvious_patterns(self, password):
        """Check for obvious patterns"""
        patterns = [
            r'123', r'abc', r'qwe', r'asd', r'password',
            r'(\w)\1{2,}',  # Repeated characters
            r'(.)\1{2,}',   # Any repeated character
        ]
        
        for pattern in patterns:
            if re.search(pattern, password.lower()):
                return True
        return False
        
    def calculate_entropy(self, password):
        """Calculate password entropy (randomness)"""
        if not password:
            return 0
            
        # Count character types
        char_sets = {
            'lowercase': len(re.findall(r'[a-z]', password)),
            'uppercase': len(re.findall(r'[A-Z]', password)),
            'digits': len(re.findall(r'\d', password)),
            'special': len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password))
        }
        
        # Calculate entropy
        charset_size = 0
        if char_sets['lowercase'] > 0:
            charset_size += 26
        if char_sets['uppercase'] > 0:
            charset_size += 26
        if char_sets['digits'] > 0:
            charset_size += 10
        if char_sets['special'] > 0:
            charset_size += 32
            
        if charset_size == 0:
            return 0
            
        entropy = len(password) * (charset_size ** 0.5) / 100
        return entropy
        
    def calculate_strength_score(self, checks, password):
        """Calculate comprehensive strength score"""
        score = 0
        
        # Base criteria (40 points)
        for check in ['length', 'uppercase', 'lowercase', 'number', 'special']:
            if checks[check]:
                score += 8
                
        # Advanced criteria (30 points)
        if checks['not_common']:
            score += 10
        if checks['no_patterns']:
            score += 10
        if checks['entropy']:
            score += 10
            
        # Length bonus (20 points)
        if len(password) >= 12:
            score += 20
        elif len(password) >= 10:
            score += 15
        elif len(password) >= 8:
            score += 10
            
        # Complexity bonus (10 points)
        criteria_met = sum(checks.values())
        if criteria_met >= 6:
            score += 10
        elif criteria_met >= 4:
            score += 5
            
        return min(score, 100)
        
    def update_ui(self, checks, strength_score, password):
        """Update the user interface with analysis results"""
        # Update strength meter
        self.strength_bar['value'] = strength_score
        
        # Determine strength level
        if strength_score >= 80:
            strength_text = f"Strong ({strength_score}/100)"
            self.strength_label.config(foreground='#27ae60')
        elif strength_score >= 60:
            strength_text = f"Good ({strength_score}/100)"
            self.strength_label.config(foreground='#f39c12')
        elif strength_score >= 40:
            strength_text = f"Fair ({strength_score}/100)"
            self.strength_label.config(foreground='#e67e22')
        else:
            strength_text = f"Weak ({strength_score}/100)"
            self.strength_label.config(foreground='#e74c3c')
            
        self.strength_label.config(text=f"Password Strength: {strength_text}")
        
        # Update criteria labels
        for criterion, passed in checks.items():
            label = self.criteria_labels[criterion]
            if passed:
                label.config(text=f"✅ {label.cget('text')[2:]}")
            else:
                label.config(text=f"❌ {label.cget('text')[2:]}")
                
        # Update advanced analysis
        self.update_advanced_analysis(password, checks, strength_score)
        
        # Update recommendations
        self.update_recommendations(checks, password, strength_score)
        
        # Add to history
        self.add_to_history(password, strength_score)
        
    def update_advanced_analysis(self, password, checks, strength_score):
        """Update advanced analysis display"""
        # Calculate character counts
        lowercase_count = len(re.findall(r'[a-z]', password))
        uppercase_count = len(re.findall(r'[A-Z]', password))
        digits_count = len(re.findall(r'\d', password))
        special_count = len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password))
        
        analysis = f"""Password Analysis Report:
{'='*50}
Length: {len(password)} characters
Entropy Score: {self.calculate_entropy(password):.2f}
Strength Score: {strength_score}/100

Character Analysis:
- Lowercase: {lowercase_count}
- Uppercase: {uppercase_count}
- Digits: {digits_count}
- Special: {special_count}

Security Checks:
- Common Password: {'❌' if not checks['not_common'] else '✅'}
- Pattern Detection: {'❌' if not checks['no_patterns'] else '✅'}
- Entropy Level: {'❌' if not checks['entropy'] else '✅'}

Hash (SHA-256): {hashlib.sha256(password.encode()).hexdigest()[:32]}...
"""
        
        self.analysis_text.delete(1.0, tk.END)
        self.analysis_text.insert(1.0, analysis)
        
    def update_recommendations(self, checks, password, strength_score):
        """Update security recommendations"""
        recommendations = []
        
        if not checks['length']:
            recommendations.append("• Make your password at least 8 characters long")
        elif len(password) < 12:
            recommendations.append("• Consider making your password 12+ characters for better security")
            
        if not checks['uppercase']:
            recommendations.append("• Add at least one uppercase letter (A-Z)")
        if not checks['lowercase']:
            recommendations.append("• Add at least one lowercase letter (a-z)")
        if not checks['number']:
            recommendations.append("• Add at least one number (0-9)")
        if not checks['special']:
            recommendations.append("• Add at least one special character (!@#$%^&*)")
        if not checks['not_common']:
            recommendations.append("• Avoid common passwords - choose something unique")
        if not checks['no_patterns']:
            recommendations.append("• Avoid obvious patterns like '123' or repeated characters")
        if not checks['entropy']:
            recommendations.append("• Increase randomness by mixing character types")
            
        if strength_score >= 80:
            recommendations.append("\n🎉 Excellent! Your password is very secure.")
        elif strength_score >= 60:
            recommendations.append("\n👍 Good password! Consider the suggestions above for even better security.")
        else:
            recommendations.append("\n⚠️ Your password needs improvement. Follow the suggestions above.")
            
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(1.0, "\n".join(recommendations))
        
    def generate_secure_password(self):
        """Generate a cryptographically secure password"""
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill the rest randomly
        all_chars = lowercase + uppercase + digits + special
        for _ in range(12):  # Total length: 16
            password.append(secrets.choice(all_chars))
            
        # Shuffle the password
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        secure_password = ''.join(password_list)
        
        # Set the password
        self.password_var.set(secure_password)
        
        # Show success message
        messagebox.showinfo("Password Generated", 
                           f"Secure password generated!\n\n{secure_password}\n\nThis password meets all security criteria.")
        
    def add_to_history(self, password, strength_score):
        """Add password to history (for analysis purposes)"""
        if password:
            timestamp = datetime.now().isoformat()
            entry = {
                'timestamp': timestamp,
                'length': len(password),
                'strength_score': strength_score,
                'hash': hashlib.sha256(password.encode()).hexdigest()
            }
            
            self.password_history.append(entry)
            
            # Keep only recent history
            if len(self.password_history) > self.max_history:
                self.password_history.pop(0)
                
    def clear_all(self):
        """Clear all fields and reset analysis"""
        self.password_var.set("")
        self.reset_analysis()
        
    def reset_analysis(self):
        """Reset all analysis displays"""
        self.strength_bar['value'] = 0
        self.strength_label.config(text="Password Strength: Enter a password", foreground='#ecf0f1')
        
        # Reset criteria labels
        for criterion in self.criteria_labels:
            label = self.criteria_labels[criterion]
            label.config(text=f"❌ {label.cget('text')[2:]}")
            
        # Clear analysis and results
        self.analysis_text.delete(1.0, tk.END)
        self.results_text.delete(1.0, tk.END)
        
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = PasswordComplexityChecker()
    app.run()
