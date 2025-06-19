import Box from "@mui/material/Box";
import Typography from "@mui/material/Typography";
import Button from "@mui/material/Button";
import Checkbox from "@mui/material/Checkbox";
import FormControlLabel from "@mui/material/FormControlLabel";
import {Clear, Download, Settings} from "@mui/icons-material";
import {useState} from "react";

const OptionsPanel = ({ onClearAll, fileInfo }) => {
    const [checkbox1, setCheckbox1] = useState(false);
    const [checkbox2, setCheckbox2] = useState(false);
    const [checkbox3, setCheckbox3] = useState(false);

    const handleClearAll = () => {
        console.log("Clear All button clicked");
        if (onClearAll) {
            onClearAll();
        }
    };

    const handleExportLinux = () => {
        console.log("Linux (Apache) clicked");
    };

    const handleExportWindows = () => {
        console.log("Windows (IIS) clicked");
    };

    const handleExportAdvanced = () => {
        console.log("ADVANCED clicked");
    };

    const formatFileSize = (bytes) => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    return (
        <Box sx={{
            width: '250px',
            backgroundColor: 'lightgray',
            borderRadius: '10px',
            padding: '15px',
            display: 'flex',
            flexDirection: 'column',
            gap: 2,
        }}>
            <Typography variant="h6" sx={{
                textAlign: 'center',
                fontWeight: 'bold',
                color: 'rgb(1, 111, 157)',
                mb: 1,
            }}>
                Options
            </Typography>

            {/* Input Section */}
            <Box sx={{
                backgroundColor: 'white',
                borderRadius: '8px',
                padding: '10px',
                mb: 1,
            }}>
                <Typography variant="subtitle1" sx={{
                    fontWeight: 'bold',
                    color: 'rgb(1, 111, 157)',
                    mb: 1,
                }}>
                    Input Section
                </Typography>
                <Button
                    variant="contained"
                    startIcon={<Clear />}
                    onClick={handleClearAll}
                    sx={{
                        backgroundColor: 'rgb(164, 0, 29)',
                        color: 'white',
                        width: '100%',
                        '&:hover': {
                            backgroundColor: 'rgb(140, 0, 25)',
                        },
                    }}
                >
                    Clear All
                </Button>
            </Box>

            {/* Checkbox Section */}
            <Box sx={{
                backgroundColor: 'white',
                borderRadius: '8px',
                padding: '10px',
                mb: 1,
            }}>
                <Typography variant="subtitle1" sx={{
                    fontWeight: 'bold',
                    color: 'rgb(1, 111, 157)',
                    mb: 1,
                }}>
                    Options
                </Typography>
                <Box sx={{
                    display: 'flex',
                    flexDirection: 'column',
                }}>
                    <FormControlLabel
                        control={
                            <Checkbox
                                checked={checkbox1}
                                onChange={(e) => setCheckbox1(e.target.checked)}
                                sx={{
                                    color: 'rgb(1, 111, 157)',
                                    '&.Mui-checked': {
                                        color: 'rgb(1, 111, 157)',
                                    },
                                }}
                            />
                        }
                        label="Checkbox1"
                    />
                    <FormControlLabel
                        control={
                            <Checkbox
                                checked={checkbox2}
                                onChange={(e) => setCheckbox2(e.target.checked)}
                                sx={{
                                    color: 'rgb(1, 111, 157)',
                                    '&.Mui-checked': {
                                        color: 'rgb(1, 111, 157)',
                                    },
                                }}
                            />
                        }
                        label="Checkbox2"
                    />
                    <FormControlLabel
                        control={
                            <Checkbox
                                checked={checkbox3}
                                onChange={(e) => setCheckbox3(e.target.checked)}
                                sx={{
                                    color: 'rgb(1, 111, 157)',
                                    '&.Mui-checked': {
                                        color: 'rgb(1, 111, 157)',
                                    },
                                }}
                            />
                        }
                        label="Checkbox3"
                    />
                </Box>
            </Box>

            {/* Export Section */}
            <Box sx={{
                backgroundColor: 'white',
                borderRadius: '8px',
                padding: '10px',
                mb: 1,
            }}>
                <Typography variant="subtitle1" sx={{
                    fontWeight: 'bold',
                    color: 'rgb(1, 111, 157)',
                    mb: 1,
                }}>
                    Export
                </Typography>
                <Box sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 1,
                }}>
                    <Button
                        variant="contained"
                        startIcon={<Download />}
                        onClick={handleExportLinux}
                        sx={{
                            backgroundColor: 'rgb(1, 111, 157)',
                            color: 'white',
                            width: '100%',
                            '&:hover': {
                                backgroundColor: 'rgb(1, 90, 130)',
                            },
                        }}
                    >
                        Linux (Apache)
                    </Button>

                    <Button
                        variant="contained"
                        startIcon={<Download />}
                        onClick={handleExportWindows}
                        sx={{
                            backgroundColor: 'rgb(1, 111, 157)',
                            color: 'white',
                            width: '100%',
                            '&:hover': {
                                backgroundColor: 'rgb(1, 90, 130)',
                            },
                        }}
                    >
                        Windows (IIS)
                    </Button>

                    <Button
                        variant="contained"
                        startIcon={<Settings />}
                        onClick={handleExportAdvanced}
                        sx={{
                            backgroundColor: 'rgb(255, 140, 0)',
                            color: 'white',
                            width: '100%',
                            '&:hover': {
                                backgroundColor: 'rgb(230, 120, 0)',
                            },
                        }}
                    >
                        ADVANCED
                    </Button>
                </Box>
            </Box>

            {/* File Information Section */}
            <Box sx={{
                backgroundColor: 'rgba(255, 255, 255, 0.7)',
                borderRadius: '8px',
                padding: '8px',
                border: '1px solid rgba(0, 0, 0, 0.1)',
            }}>
                <Typography variant="caption" sx={{
                    fontWeight: 'normal',
                    color: 'rgba(1, 111, 157, 0.7)',
                    mb: 0.5,
                    fontSize: '11px',
                }}>
                    File Information
                </Typography>
                <Box sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 0.5,
                }}>
                    <Box sx={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                    }}>
                        <Typography variant="caption" sx={{ 
                            fontWeight: 'normal',
                            color: 'rgba(0, 0, 0, 0.5)',
                            fontSize: '10px',
                        }}>
                            Filename:
                        </Typography>
                        <Typography variant="caption" sx={{ 
                            color: 'rgba(0, 0, 0, 0.4)',
                            maxWidth: '140px',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            fontSize: '10px',
                        }}>
                            {fileInfo?.fileName || 'None'}
                        </Typography>
                    </Box>
                    <Box sx={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                    }}>
                        <Typography variant="caption" sx={{ 
                            fontWeight: 'normal',
                            color: 'rgba(0, 0, 0, 0.5)',
                            fontSize: '10px',
                        }}>
                            File Size:
                        </Typography>
                        <Typography variant="caption" sx={{ 
                            color: 'rgba(0, 0, 0, 0.4)',
                            fontSize: '10px',
                        }}>
                            {fileInfo?.fileSize ? formatFileSize(fileInfo.fileSize) : '0 Bytes'}
                        </Typography>
                    </Box>
                </Box>
            </Box>
        </Box>
    );
};

export default OptionsPanel;