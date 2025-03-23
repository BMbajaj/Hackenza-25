from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import os
import shutil
from pathlib import Path

app = FastAPI()

# Configure CORS to allow requests from your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development; restrict to your actual domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create upload directory if it doesn't exist
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

@app.post("/upload-multiple/")
async def upload_multiple_files(files: List[UploadFile] = File(...)):
    """
    Endpoint for uploading multiple files simultaneously.
    Returns the list of successfully uploaded filenames.
    Rejects any files that already exist on the server.
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files were uploaded")
    
    # Get existing filenames (case insensitive)
    existing_files = set()
    for file_path in UPLOAD_DIR.glob("*"):
        if file_path.is_file():
            existing_files.add(file_path.name.lower())
    
    # Check for duplicates
    duplicates = []
    for file in files:
        if file.filename.lower() in existing_files:
            duplicates.append(file.filename)
    
    # If duplicates found, reject the entire upload
    if duplicates:
        duplicate_list = ", ".join(duplicates)
        raise HTTPException(
            status_code=409, 
            detail=f"Duplicate files detected: {duplicate_list}. Upload rejected."
        )
    
    saved_filenames = []
    
    try:
        for file in files:
            # Create a safe filename
            filename = Path(file.filename)
            file_path = UPLOAD_DIR / filename
            
            # Save the file
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            
            saved_filenames.append(str(file_path.name))
            
    except Exception as e:
        # If anything goes wrong, cleanup any partially uploaded files
        for filename in saved_filenames:
            try:
                (UPLOAD_DIR / filename).unlink(missing_ok=True)
            except:
                pass
        raise HTTPException(status_code=500, detail=f"An error occurred during upload: {str(e)}")
    
    return {"filenames": saved_filenames, "message": f"Successfully uploaded {len(saved_filenames)} files"}

@app.get("/")
async def root():
    return {"message": "File upload API is running. Use /upload-multiple/ endpoint to upload files."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)