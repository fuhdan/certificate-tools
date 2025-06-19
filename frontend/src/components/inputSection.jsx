import {useState, useRef, forwardRef, useImperativeHandle} from "react";
import Box from "@mui/material/Box";
import Typography from "@mui/material/Typography";
import TextField from "@mui/material/TextField";
import {CloudUpload} from "@mui/icons-material";

const InputSection = forwardRef(({ onDataReceived }, ref) => {
    const [inputText, setInputText] = useState('');
    const [isDragOver, setIsDragOver] = useState(false);
    const [fileName, setFileName] = useState('');
    const fileInputRef = useRef(null);

    // Expose clearAll method to parent
    useImperativeHandle(ref, () => ({
        clearAll: () => {
            console.log("InputSection: clearAll called");
            setInputText('');
            setFileName('');
            if (onDataReceived) {
                onDataReceived('', 'clear');
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

    const handleFileUpload = (file) => {
        if (file) {
            setFileName(file.name);
            const reader = new FileReader();
            reader.onload = (e) => {
                const content = e.target.result;
                console.log("InputSection: file uploaded, content:", content, "size:", file.size);
                setInputText(content);
                if (onDataReceived) {
                    onDataReceived(content, 'file', file.name, file.size);
                }
            };
            reader.readAsText(file);
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
                placeholder="Paste your text here..."
                value={inputText}
                onChange={handleTextChange}
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
                    cursor: 'pointer',
                    transition: 'all 0.3s ease',
                    height: '80px',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                }}
            >
                <CloudUpload sx={{ 
                    fontSize: '30px', 
                    color: isDragOver ? 'rgb(1, 111, 157)' : '#999',
                    marginBottom: '5px',
                }} />
                <Typography variant="body2" sx={{ color: '#666' }}>
                    {fileName ? `File: ${fileName}` : 'Drag & drop file or click to browse'}
                </Typography>
            </Box>

            {/* Hidden File Input */}
            <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileSelect}
                accept=".txt,.csv,.json"
                style={{ display: 'none' }}
            />
        </Box>
    );
});

InputSection.displayName = 'InputSection';

export default InputSection;