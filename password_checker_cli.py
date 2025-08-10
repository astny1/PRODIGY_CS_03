#!/usr/bin/env python3
"""
Password Complexity Checker - Command Line Interface
Advanced security analysis tool for password strength assessment
"""

import argparse
import re
import secrets
import string
import hashlib
import json
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Set
import getpass

class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
        self.breach_database = self.load_breach_database()
        
    def load_common_passwords(self) -> Set[str]:
        """Load common passwords database"""
        common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'sunshine', 'princess', 'qwerty123',
            'football', 'baseball', 'superman', 'batman', 'trustno1',
            'hello', 'freedom', 'whatever', 'qazwsx', 'login',
            'starwars', 'dragon', 'passw0rd', 'master', 'hello123',
            'freedom', 'qwertyuiop', 'letmein123', 'admin123', 'welcome123'
        }
        return common_passwords
        
    def load_breach_database(self) -> Set[str]:
        """Load breach database (simplified version)"""
        # In a real implementation, this would load from a large database
        # of known compromised passwords
        return set()  # Placeholder for breach database
        
    def analyze_password(self, password: str) -> Dict:
        """Comprehensive password analysis"""
        if not password:
            return self.get_empty_analysis()
            
        # Basic criteria checks
        checks = {
            'length': len(password) >= 8,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'number': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password)),
            'not_common': password.lower() not in self.common_passwords,
            'no_patterns': not self.has_obvious_patterns(password),
            'entropy': self.calculate_entropy(password) > 3.0,
            'not_breached': password.lower() not in self.breach_database
        }
        
        # Calculate comprehensive score
        strength_score = self.calculate_strength_score(checks, password)
        
        # Determine strength level
        strength_level = self.get_strength_level(strength_score)
        
        # Generate recommendations
        recommendations = self.generate_recommendations(checks, password, strength_score)
        
        return {
            'password': password,
            'length': len(password),
            'checks': checks,
            'strength_score': strength_score,
            'strength_level': strength_level,
            'entropy': self.calculate_entropy(password),
            'hash_sha256': hashlib.sha256(password.encode()).hexdigest(),
            'recommendations': recommendations,
            'timestamp': datetime.now().isoformat(),
            'character_analysis': self.analyze_characters(password)
        }
        
    def get_empty_analysis(self) -> Dict:
        """Return empty analysis structure"""
        return {
            'password': '',
            'length': 0,
            'checks': {},
            'strength_score': 0,
            'strength_level': 'None',
            'entropy': 0,
            'hash_sha256': '',
            'recommendations': ['Enter a password to analyze'],
            'timestamp': datetime.now().isoformat(),
            'character_analysis': {}
        }
        
    def has_obvious_patterns(self, password: str) -> bool:
        """Check for obvious patterns in password"""
        patterns = [
            r'123', r'abc', r'qwe', r'asd', r'password',
            r'(\w)\1{2,}',  # Repeated characters
            r'(.)\1{2,}',   # Any repeated character
            r'qwerty', r'asdfgh', r'zxcvbn',
            r'111', r'222', r'333', r'000',
            r'aaa', r'bbb', r'ccc'
        ]
        
        password_lower = password.lower()
        for pattern in patterns:
            if re.search(pattern, password_lower):
                return True
        return False
        
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy (randomness measure)"""
        if not password:
            return 0.0
            
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
            return 0.0
            
        # Entropy calculation using Shannon's formula
        entropy = len(password) * (charset_size ** 0.5) / 100
        return entropy
        
    def calculate_strength_score(self, checks: Dict, password: str) -> int:
        """Calculate comprehensive strength score (0-100)"""
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
        
    def get_strength_level(self, score: int) -> str:
        """Get strength level based on score"""
        if score >= 80:
            return 'Strong'
        elif score >= 60:
            return 'Good'
        elif score >= 40:
            return 'Fair'
        else:
            return 'Weak'
            
    def analyze_characters(self, password: str) -> Dict:
        """Analyze character distribution"""
        return {
            'lowercase': len(re.findall(r'[a-z]', password)),
            'uppercase': len(re.findall(r'[A-Z]', password)),
            'digits': len(re.findall(r'\d', password)),
            'special': len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password)),
            'total': len(password)
        }
        
    def generate_recommendations(self, checks: Dict, password: str, score: int) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if not checks['length']:
            recommendations.append("Make your password at least 8 characters long")
        elif len(password) < 12:
            recommendations.append("Consider making your password 12+ characters for better security")
            
        if not checks['uppercase']:
            recommendations.append("Add at least one uppercase letter (A-Z)")
        if not checks['lowercase']:
            recommendations.append("Add at least one lowercase letter (a-z)")
        if not checks['number']:
            recommendations.append("Add at least one number (0-9)")
        if not checks['special']:
            recommendations.append("Add at least one special character (!@#$%^&*)")
        if not checks['not_common']:
            recommendations.append("Avoid common passwords - choose something unique")
        if not checks['no_patterns']:
            recommendations.append("Avoid obvious patterns like '123' or repeated characters")
        if not checks['entropy']:
            recommendations.append("Increase randomness by mixing character types")
        if not checks['not_breached']:
            recommendations.append("This password has been found in data breaches - choose a different one")
            
        if score >= 80:
            recommendations.append("Excellent! Your password is very secure.")
        elif score >= 60:
            recommendations.append("Good password! Consider the suggestions above for even better security.")
        else:
            recommendations.append("Your password needs improvement. Follow the suggestions above.")
            
        return recommendations
        
    def generate_secure_password(self, length: int = 16) -> str:
        """Generate a cryptographically secure password"""
        if length < 8:
            length = 8
            
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
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
            
        # Shuffle the password
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        return ''.join(password_list)
        
    def print_analysis(self, analysis: Dict, verbose: bool = False):
        """Print analysis results in a formatted way"""
        print("\n" + "="*60)
        print("🔒 PASSWORD COMPLEXITY ANALYSIS")
        print("="*60)
        
        if not analysis['password']:
            print("❌ No password provided for analysis")
            return
            
        # Basic info
        print(f"📊 Password Length: {analysis['length']} characters")
        print(f"🎯 Strength Score: {analysis['strength_score']}/100")
        print(f"📈 Strength Level: {analysis['strength_level']}")
        print(f"🔢 Entropy Score: {analysis['entropy']:.2f}")
        
        # Character analysis
        char_analysis = analysis['character_analysis']
        print(f"\n📝 Character Analysis:")
        print(f"   • Lowercase: {char_analysis['lowercase']}")
        print(f"   • Uppercase: {char_analysis['uppercase']}")
        print(f"   • Digits: {char_analysis['digits']}")
        print(f"   • Special: {char_analysis['special']}")
        
        # Security checks
        print(f"\n✅ Security Checks:")
        checks = analysis['checks']
        for check, passed in checks.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            check_name = check.replace('_', ' ').title()
            print(f"   • {check_name}: {status}")
            
        # Recommendations
        print(f"\n💡 Recommendations:")
        for i, rec in enumerate(analysis['recommendations'], 1):
            print(f"   {i}. {rec}")
            
        if verbose:
            print(f"\n🔐 Hash (SHA-256): {analysis['hash_sha256']}")
            print(f"⏰ Analysis Time: {analysis['timestamp']}")
            
        print("="*60)

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Password Complexity Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_checker_cli.py                    # Interactive mode
  python password_checker_cli.py -p "MyPassword123!" # Check specific password
  python password_checker_cli.py -g                 # Generate secure password
  python password_checker_cli.py -g -l 20          # Generate 20-char password
  python password_checker_cli.py -v -p "test123"   # Verbose analysis
        """
    )
    
    parser.add_argument('-p', '--password', 
                       help='Password to analyze')
    parser.add_argument('-g', '--generate', 
                       action='store_true',
                       help='Generate a secure password')
    parser.add_argument('-l', '--length', 
                       type=int, default=16,
                       help='Length for generated password (default: 16)')
    parser.add_argument('-v', '--verbose', 
                       action='store_true',
                       help='Verbose output with additional details')
    parser.add_argument('-j', '--json', 
                       action='store_true',
                       help='Output results in JSON format')
    parser.add_argument('-f', '--file', 
                       help='Save results to file')
    
    args = parser.parse_args()
    
    analyzer = PasswordAnalyzer()
    
    try:
        if args.generate:
            # Generate secure password
            secure_password = analyzer.generate_secure_password(args.length)
            print(f"\n🔐 Generated Secure Password: {secure_password}")
            
            # Analyze the generated password
            analysis = analyzer.analyze_password(secure_password)
            if not args.json:
                analyzer.print_analysis(analysis, args.verbose)
            else:
                print(json.dumps(analysis, indent=2))
                
        elif args.password:
            # Analyze provided password
            analysis = analyzer.analyze_password(args.password)
            if not args.json:
                analyzer.print_analysis(analysis, args.verbose)
            else:
                print(json.dumps(analysis, indent=2))
                
        else:
            # Interactive mode
            print("🔒 Password Complexity Checker - Interactive Mode")
            print("Enter 'quit' to exit, 'generate' to create a secure password")
            
            while True:
                try:
                    password = getpass.getpass("\nEnter password to analyze: ")
                    
                    if password.lower() == 'quit':
                        print("👋 Goodbye!")
                        break
                    elif password.lower() == 'generate':
                        secure_password = analyzer.generate_secure_password()
                        print(f"\n🔐 Generated Password: {secure_password}")
                        continue
                    elif not password:
                        print("❌ Please enter a password")
                        continue
                        
                    analysis = analyzer.analyze_password(password)
                    analyzer.print_analysis(analysis, args.verbose)
                    
                except KeyboardInterrupt:
                    print("\n👋 Goodbye!")
                    break
                except Exception as e:
                    print(f"❌ Error: {e}")
                    
        # Save to file if requested
        if args.file and 'analysis' in locals():
            try:
                with open(args.file, 'w') as f:
                    json.dump(analysis, f, indent=2)
                print(f"\n💾 Results saved to {args.file}")
            except Exception as e:
                print(f"❌ Error saving to file: {e}")
                
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
