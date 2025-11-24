import os
import time

"""
Simple test script that overwrites files in a target folder with random bytes
to simulate encryption activity. USE WITH CAUTION — for testing only.
"""

TARGET_FOLDER = r"ransom_test"   # Change to your test folder

if not os.path.exists(TARGET_FOLDER):
	print('Target folder not found:', TARGET_FOLDER)
else:
	for fname in os.listdir(TARGET_FOLDER):
		full_path = os.path.join(TARGET_FOLDER, fname)
		if os.path.isfile(full_path):
			try:
				with open(full_path, "wb") as f:
					f.write(os.urandom(4096))
				print(f"Encrypted: {fname}")
				time.sleep(0.1)   # Small delay to look realistic
			except Exception as e:
				print('Failed to modify', full_path, e)
