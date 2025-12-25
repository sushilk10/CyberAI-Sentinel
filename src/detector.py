import joblib
import numpy as np
import pandas as pd

class CyberAI_Detector:
    """
    🛡️ PRODUCTION-READY CYBERSECURITY AI DETECTOR
    =============================================
    Features:
    - Adjustable sensitivity (threshold)
    - Multiple alert levels
    - Logging capability
    - Batch processing
    """
    
    def __init__(self, threshold=0.35):
        """Initialize detector with sensitivity threshold"""
        print("🔧 Initializing CyberAI Detector...")
        
        # Load trained model and preprocessors
        try:
            self.model = joblib.load('models/best_model.pkl')
            self.scaler = joblib.load('models/scaler.pkl')
            self.encoders = joblib.load('models/encoders.pkl')
            print("✅ AI Model loaded successfully!")
        except:
            print("⚠️  Models not found. Run training first.")
            self.model = None
            
        # Configuration
        self.threshold = threshold
        
        # 🛡️ RULE ENGINE (Hybrid Defense)
        # trusted_ips: Always ALLOW (Verdict: Safe)
        # blocked_ips: Always BLOCK (Verdict: Critical)
        self.trusted_ips = {"192.168.1.1", "10.0.0.1"} # Example: Admin IPs
        self.blocked_ips = {"192.168.1.100", "1.1.1.1"} # Example: Known attackers
        
        self.alert_levels = {
            'INFO': '📊 Monitor',
            'LOW': '⚠️  Low Risk',
            'MEDIUM': '🚨 Investigate',
            'HIGH': '🔥 High Threat',
            'CRITICAL': '💀 CRITICAL ATTACK'
        }
        
        print(f"🔐 Detection threshold: {self.threshold:.0%}")
        print(f"📝 Rules loaded: {len(self.trusted_ips)} Allowed, {len(self.blocked_ips)} Blocked")
        print("="*50)

    def update_rules(self, action, ip, rule_type):
        """Update the rule sets dynamically"""
        target_set = self.trusted_ips if rule_type == "whitelist" else self.blocked_ips
        
        if action == "add":
            target_set.add(ip)
            # Ensure IP isn't in both lists
            other_set = self.blocked_ips if rule_type == "whitelist" else self.trusted_ips
            if ip in other_set:
                other_set.remove(ip)
            return True
            
        elif action == "remove":
            if ip in target_set:
                target_set.remove(ip)
                return True
        
        return False

    def get_rules(self):
        return {
            "whitelist": list(self.trusted_ips),
            "blacklist": list(self.blocked_ips)
        }
    
    def get_alert_level(self, probability):
        """Determine alert level based on probability"""
        if probability > 0.7:
            return 'CRITICAL'
        elif probability > 0.5:
            return 'HIGH'
        elif probability > 0.35:  # Our threshold
            return 'MEDIUM'
        elif probability > 0.2:
            return 'LOW'
        else:
            return 'INFO'
    
    def analyze(self, connection_features, ip_address=None):
        """
        Analyze a single connection using Hybrid Logic:
        1. Check Rules (Whitelist/Blacklist)
        2. If no rule matches, use AI Model
        """
        
        # 1️⃣ RULE CHECK
        if ip_address:
            # Check Whitelist
            if ip_address in self.trusted_ips:
                return {
                    'is_attack': False,
                    'attack_probability': 0.0,
                    'alert_level': 'INFO',
                    'emoji': '🛡️ Safe',
                    'message': f"RULE ENGINE: Allowed Trusted IP {ip_address}",
                    'recommendation': "Whitelisted - No action required"
                }
            
            # Check Blacklist
            if ip_address in self.blocked_ips:
                return {
                    'is_attack': True,
                    'attack_probability': 1.0,
                    'alert_level': 'CRITICAL',
                    'emoji': '🚫 Blocked',
                    'message': f"RULE ENGINE: Blocked Malicious IP {ip_address}",
                    'recommendation': "Blacklisted - Auto-Blocked"
                }

        # 2️⃣ AI ANALYSIS (Fallback)
        if self.model is None:
            return {"error": "Model not loaded"}
        
        # Get prediction
        probability = self.model.predict_proba([connection_features])[0][1]
        alert_level = self.get_alert_level(probability)
        
        # Determine if it's an attack (based on threshold)
        is_attack = bool(probability > self.threshold)
        
        result = {
            'is_attack': is_attack,
            'attack_probability': float(probability),
            'alert_level': alert_level,
            'emoji': self.alert_levels[alert_level],
            'message': f"{self.alert_levels[alert_level]} - {probability:.1%} attack confidence",
            'recommendation': self.get_recommendation(is_attack, alert_level)
        }
        
        return result
    
    def analyze_batch(self, connections_list):
        """Analyze multiple connections at once"""
        results = []
        for i, connection in enumerate(connections_list):
            result = self.analyze(connection)
            result['connection_id'] = i
            results.append(result)
        
        # Summary
        attacks = sum(1 for r in results if r['is_attack'])
        total = len(results)
        
        summary = {
            'total_connections': total,
            'detected_attacks': attacks,
            'attack_rate': f"{attacks/total:.1%}" if total > 0 else "0%",
            'results': results
        }
        
        return summary
    
    def get_recommendation(self, is_attack, alert_level):
        """Get action recommendation based on threat level"""
        if alert_level == 'CRITICAL':
            return "IMMEDIATE ACTION: Block IP, isolate system, alert team"
        elif alert_level == 'HIGH':
            return "URGENT: Investigate, monitor closely, prepare response"
        elif alert_level == 'MEDIUM':
            return "INVESTIGATE: Review logs, check patterns, monitor"
        elif alert_level == 'LOW':
            return "MONITOR: Keep in watchlist, log for trends"
        else:
            return "NORMAL: No action required"
    
    def test_scenarios(self):
        """Test with predefined scenarios"""
        print("\n🧪 TESTING WITH PRE-DEFINED SCENARIOS")
        print("="*50)
        
        # Test cases (simplified - just key features)
        scenarios = [
            {
                "name": "Normal Web Browsing",
                "features": [0.1, 1, 2, 3, 100, 50000] + [0]*35
            },
            {
                "name": "Brute Force Attack",
                "features": [120.0, 1, 2, 3, 5000, 5000, 0, 0, 0, 0, 15, 0] + [0]*5 + [10, 10, 0.5, 0.5, 0.5, 0.5, 0.1, 0.9, 0.8, 10, 10, 0.1, 0.9, 0.8, 0.8, 0.5, 0.5, 0.5, 0.5]
            },
            {
                "name": "Port Scanning",
                "features": [0.5, 1, 0, 3, 50, 0] + [0]*5 + [0, 0] + [0]*5 + [100, 100, 0.8, 0.8, 0.8, 0.8, 0.0, 1.0, 1.0, 100, 100, 0.0, 1.0, 1.0, 1.0, 0.8, 0.8, 0.8, 0.8]
            }
        ]
        
        for scenario in scenarios:
            # Make sure we have 41 features
            features = scenario['features']
            if len(features) < 41:
                features = features + [0] * (41 - len(features))
            elif len(features) > 41:
                features = features[:41]
            
            result = self.analyze(features)
            
            print(f"\n📋 {scenario['name']}:")
            print(f"   {result['emoji']}")
            print(f"   Attack Probability: {result['attack_probability']:.1%}")
            print(f"   Verdict: {'🚨 ATTACK' if result['is_attack'] else '✅ NORMAL'}")
            print(f"   Action: {result['recommendation']}")

# 🚀 USAGE EXAMPLE
if __name__ == "__main__":
    print("🛡️ CYBERSECURITY AI PRODUCTION SYSTEM")
    print("="*50)
    
    # Create detector with 35% threshold (balanced)
    detector = CyberAI_Detector(threshold=0.35)
    
    # Test it
    detector.test_scenarios()
    
    print("\n" + "="*50)
    print("📊 HOW TO USE IN YOUR PROJECT:")
    print("="*50)
    print("""
# 1. Import the detector
from production_detector import CyberAI_Detector

# 2. Create instance (adjust threshold as needed)
detector = CyberAI_Detector(threshold=0.35)

# 3. Analyze a connection
connection_data = [...]  # 41 features
result = detector.analyze(connection_data)

# 4. Take action based on result
if result['is_attack']:
    print(f"ALERT: {result['message']}")
    print(f"ACTION: {result['recommendation']}")
    
# 5. Or analyze multiple connections
results = detector.analyze_batch([connection1, connection2, ...])
    """)
    
    print("\n" + "="*50)
    print("✅ PRODUCTION SYSTEM READY!")
    print("="*50)