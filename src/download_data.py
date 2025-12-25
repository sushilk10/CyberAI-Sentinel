import os
import requests
import sys

def download_file(url, filename):
    print(f"⬇️ Downloading {filename} from {url}...")
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"✅ Download complete: {filename}")
        return True
    except Exception as e:
        print(f"❌ Error downloading {filename}: {e}")
        return False

if __name__ == "__main__":
    # Create data directory
    if not os.path.exists('data'):
        os.makedirs('data')
        
    # Official NSL-KDD Repository URL
    url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
    filepath = "data/KDDTrain+.txt"
    
    if os.path.exists(filepath):
        print(f"ℹ️ File already exists: {filepath}")
    else:
        success = download_file(url, filepath)
        if not success:
            print("⚠️ Failed to download data. Please check your internet connection.")
            sys.exit(1)
