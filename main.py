import hashlib

def get_user_input():
    """Get user input with validation"""
    try:
        ts = input("Enter timestamp: ").strip()
        if not ts:
            raise ValueError("Timestamp cannot be empty")
        
        public = input("Enter public key: ").strip()
        if not public:
            raise ValueError("Public key cannot be empty")
        
        private = input("Enter private key: ").strip()
        if not private:
            raise ValueError("Private key cannot be empty")
        
        return ts, public, private
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return None, None, None
    except EOFError:
        print("\nUnexpected end of input")
        return None, None, None

def generate_hash(ts, public, private):
    """Generate MD5 hash from the provided inputs"""
    try:
        to_hash = ts + private + public
        hashed = hashlib.md5(to_hash.encode()).hexdigest()
        return hashed
    except Exception as e:
        print(f"Error generating hash: {e}")
        return None

def main():
    """Main function to run the hash generator"""
    print("Hash Generator")
    print("-" * 20)
    
    try:
        # Get user input
        ts, public, private = get_user_input()
        
        # Check if input was successfully obtained
        if ts is None or public is None or private is None:
            print("Failed to get valid input. Exiting.")
            return
        
        # Generate hash
        hashed = generate_hash(ts, public, private)
        
        if hashed:
            print(f"\nGenerated hash: {hashed}")
        else:
            print("Failed to generate hash")
            
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
