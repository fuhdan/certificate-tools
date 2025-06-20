import {useState, useRef, forwardRef, useImperativeHandle} from "react";
import Box from "@mui/material/Box";
import Typography from "@mui/material/Typography";
import TextField from "@mui/material/TextField";
import {CloudUpload} from "@mui/icons-material";
import apiService from "../services/api.js";

const InputSection = forwardRef(({ onDataReceived, onCertificateData }, ref) => {
    const [inputText, setInputText] = useState('');
    const [isDragOver, setIsDragOver] = useState(false);
    const [fileName, setFileName] = useState('');
    const [isUploading, setIsUploading] = useState(false);
    const fileInputRef = useRef(null);

    // Expose clearAll method to parent
    useImperativeHandle(ref, () => ({
        clearAll: () => {
            console.log("InputSection: clearAll called");
            setInputText('');
            setFileName('');
            setIsUploading(false);
            if (onDataReceived) {
                onDataReceived('', 'clear');
            }
            if (onCertificateData) {
                onCertificateData(null);
            }
        }
    }));

    const handleTextChange = (event) => {
        const newValue = event.target.value;
        console.log("InputSection: text changed to:", newValue);
        setInputText(newValue);
        if (onDataReceived) {
            onDataReceived(newValue, 'text');
        }
    };

    const handleFileUpload = async (file) => {
        if (file) {
            setFileName(file.name);
            setIsUploading(true);
            
            console.log("InputSection: uploading file to API:", file.name);
            
            try {
                // Send file to API
                const result = await apiService.uploadFile(file);
                
                if (result.success) {
                    console.log("InputSection: file processed successfully:", result.data);
                    
                    // Check if it's a DER format file that needs conversion to PEM for display
                    if (result.data.fileformat === 'DER') {
                        // For DER files, show PEM format in text area
                        const arrayBuffer = await file.arrayBuffer();
                        const base64String = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
                        
                        // Format as PEM based on file type
                        let pemHeader, pemFooter;
                        if (result.data.filetype === 'certificate') {
                            pemHeader = '-----BEGIN CERTIFICATE-----';
                            pemFooter = '-----END CERTIFICATE-----';
                        } else if (result.data.filetype === 'csr') {
                            pemHeader = '-----BEGIN CERTIFICATE REQUEST-----';
                            pemFooter = '-----END CERTIFICATE REQUEST-----';
                        } else {
                            pemHeader = '-----BEGIN CERTIFICATE-----';
                            pemFooter = '-----END CERTIFICATE-----';
                        }
                        
                        // Format base64 with line breaks every 64 characters
                        const formattedBase64 = base64String.match(/.{1,64}/g).join('\n');
                        const pemContent = `${pemHeader}\n${formattedBase64}\n${pemFooter}`;
                        
                        setInputText(pemContent);
                    } else {
                        // For PEM and other text formats, display file content as-is
                        const reader = new FileReader();
                        reader.onload = (e) => {
                            setInputText(e.target.result);
                        };
                        reader.readAsText(file);
                    }
                    
                    // Notify parent components
                    if (onDataReceived) {
                        onDataReceived(file.name, 'file', file.name, file.size);
                    }
                    
                    // Send certificate data to parent for table population
                    if (onCertificateData) {
                        onCertificateData(result.data);
                    }
                } else {
                    console.error("InputSection: file upload failed:", result.error);
                    // You could show an error message here
                }
            } catch (error) {
                console.error("InputSection: file upload error:", error);
            } finally {
                setIsUploading(false);
            }
        }
    };

    const handleDragOver = (event) => {
        event.preventDefault();
        setIsDragOver(true);
    };

    const handleDragLeave = (event) => {
        event.preventDefault();
        setIsDragOver(false);
    };

    const handleDrop = (event) => {
        event.preventDefault();
        setIsDragOver(false);
        
        const files = event.dataTransfer.files;
        if (files.length > 0) {
            handleFileUpload(files[0]);
        }
    };

    const handleFileSelect = (event) => {
        const file = event.target.files[0];
        if (file) {
            handleFileUpload(file);
        }
    };

    const handleBrowseClick = () => {
        fileInputRef.current?.click();
    };

    console.log("InputSection: rendering with inputText:", inputText);

    return (
        <Box sx={{
            backgroundColor: 'white',
            borderRadius: '10px',
            padding: '15px',
            marginBottom: '10px',
            boxShadow: 2,
        }}>
            <Typography variant="h6" sx={{
                fontWeight: 'bold',
                color: 'rgb(1, 111, 157)',
                marginBottom: '10px',
            }}>
                Input Data
            </Typography>

            {/* Text Input Area - TOP */}
            <TextField
                multiline
                rows={3}
                variant="outlined"
                placeholder="Paste your text here or upload a file below..."
                value={inputText}
                onChange={handleTextChange}
                disabled={isUploading}
                sx={{
                    width: '100%',
                    marginBottom: '15px',
                    '& .MuiOutlinedInput-root': {
                        '&:hover fieldset': {
                            borderColor: 'rgb(1, 111, 157)',
                        },
                        '&.Mui-focused fieldset': {
                            borderColor: 'rgb(1, 111, 157)',
                        },
                    },
                }}
            />

            {/* Drag and Drop Area - BOTTOM */}
            <Box
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={handleBrowseClick}
                sx={{
                    border: `2px dashed ${isDragOver ? 'rgb(1, 111, 157)' : '#ccc'}`,
                    borderRadius: '8px',
                    padding: '15px',
                    textAlign: 'center',
                    backgroundColor: isDragOver ? 'rgba(1, 111, 157, 0.1)' : 'rgba(0, 0, 0, 0.02)',
                    cursor: isUploading ? 'not-allowed' : 'pointer',
                    transition: 'all 0.3s ease',
                    height: '80px',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    opacity: isUploading ? 0.6 : 1,
                }}
            >
                <CloudUpload sx={{ 
                    fontSize: '30px', 
                    color: isDragOver ? 'rgb(1, 111, 157)' : '#999',
                    marginBottom: '5px',
                }} />
                <Typography variant="body2" sx={{ color: '#666' }}>
                    {isUploading ? 'Processing file...' : 
                     fileName ? `File: ${fileName}` : 
                     'Drag & drop certificate file or click to browse'}
                </Typography>
            </Box>

            {/* Hidden File Input */}
            <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileSelect}
                accept=".csr,.crt,.pem,.der,.p7b,.p12,.pfx"
                style={{ display: 'none' }}
                disabled={isUploading}
            />
        </Box>
    );
});

InputSection.displayName = 'InputSection';

export default InputSection;