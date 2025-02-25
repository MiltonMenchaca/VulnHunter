from pymetasploit3.msfrpc import MsfRpcClient
import time

def test_connection():
    try:
        # Attempt connection
        client = MsfRpcClient('abc123', server='127.0.0.1', port=55553, ssl=False)
        
        # Verify version
        version = client.core.version
        print(f"Connection successful! Version: {version}")
        return True
        
    except Exception as e:
        print(f"Connection error: {e}")
        return False

if __name__ == "__main__":
    test_connection()
