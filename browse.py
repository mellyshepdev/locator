from flask import Flask, jsonify
import tkinter as tk
from tkinter import filedialog
from deploy import deploy_from_browse  # Importing your function

app = Flask(__name__)

@app.route('/trigger-deploy', methods=['POST'])
def trigger_deploy():
    # 1. Open the file browser (using Tkinter)
    root = tk.Tk()
    root.withdraw() # Hide the main Tkinter window
    root.attributes('-topmost', True) # Bring the dialog to the front
    
    selected_path = filedialog.askdirectory(title="Select Docker Project Folder")
    root.destroy()

    if selected_path:
        # 2. Call your deployment logic from nanodeploy/deploy.py
        # This will update your registry and run the containers
        result = deploy_from_browse(selected_path)
        return jsonify({"status": "Success", "message": f"Deployed {selected_path}"})
    
    return jsonify({"status": "Cancelled", "message": "No folder selected"})

if __name__ == '__main__':
    app.run(port=5000)

