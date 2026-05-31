// src/components/FileUploader.tsx
import React, { useRef, useState } from 'react';

interface FileUploaderProps {
  onFileSelect: (file: File) => void;
  selectedFile: File | null;
}

const FileUploader: React.FC<FileUploaderProps> = ({ onFileSelect, selectedFile }) => {
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file && (file.name.endsWith('.yaml') || file.name.endsWith('.yml') || file.name.endsWith('.json'))) {
      onFileSelect(file);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      onFileSelect(e.target.files[0]);
    }
  };

  const handleClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div
      className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all duration-200
        ${isDragging ? 'border-blue-500 bg-blue-50/10' : 'border-gray-600 bg-gray-800/30'}
        hover:border-blue-400 hover:bg-gray-800/50`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={handleClick}
    >
      <div className="text-4xl mb-3">📄</div>
      <p className="text-gray-400 text-sm">Kéo thả file OpenAPI/Swagger vào đây</p>
      <p className="text-gray-500 text-xs mt-1">hoặc <span className="text-blue-400 font-medium">click để chọn file</span></p>
      <p className="text-gray-500 text-xs mt-2">Hỗ trợ: .yaml, .yml, .json</p>
      {selectedFile && (
        <div className="mt-3 text-blue-400 text-sm font-mono">{selectedFile.name}</div>
      )}
      <input
        ref={fileInputRef}
        type="file"
        accept=".yaml,.yml,.json"
        onChange={handleFileChange}
        className="hidden"
      />
    </div>
  );
};

export default FileUploader;