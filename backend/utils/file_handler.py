import os
from typing import Tuple
from fastapi import UploadFile, HTTPException
from config import settings

class FileHandler:
    @staticmethod
    def validate_file(file: UploadFile) -> None:
        """Validate uploaded file"""
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file selected")
        
        # Check file extension
        file_ext = os.path.splitext(file.filename)[1].lower()
        if file_ext not in settings.ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400, 
                detail=f"File type not allowed. Allowed types: {', '.join(settings.ALLOWED_EXTENSIONS)}"
            )

    @staticmethod
    async def read_file_content(file: UploadFile) -> Tuple[str, int]:
        """Read and return file content with size"""
        try:
            content = await file.read()
            
            # Check file size
            if len(content) > settings.MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=413, 
                    detail=f"File too large. Maximum size: {settings.MAX_FILE_SIZE / (1024*1024):.1f}MB"
                )
            
            # Decode content
            try:
                text_content = content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    text_content = content.decode('latin-1')
                except UnicodeDecodeError:
                    raise HTTPException(status_code=400, detail="Unable to decode file. Please ensure it's a text file.")
            
            return text_content, len(content)
            
        except Exception as e:
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}")