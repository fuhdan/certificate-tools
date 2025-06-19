import {useState, useRef} from "react";
import TabContext from "@mui/lab/TabContext";
import TabList from "@mui/lab/TabList";
import Tab from "@mui/material/Tab";
import TabPanel from "@mui/lab/TabPanel";
import {SnackbarProvider} from "notistack";
import Box from "@mui/material/Box";
import {DataGrid} from "@mui/x-data-grid";
import Settings from "../components/settings.jsx";
import OptionsPanel from "../components/optionsPanel.jsx";
import InputSection from "../components/inputSection.jsx";

function Home({ isSuperuser }) {
    const [value, setValue] = useState('1');
    const [inputData, setInputData] = useState('');
    const [fileInfo, setFileInfo] = useState({ fileName: null, fileSize: 0 });
    const inputSectionRef = useRef(null);

    const handleChange = (event, newValue) => {
        setValue(newValue);
    };

    const handleDataReceived = (data, type, filename, fileSize) => {
        console.log("HOME: Data received:", { data, type, filename, fileSize });
        setInputData(data);
        
        if (type === 'file' && filename) {
            setFileInfo({ fileName: filename, fileSize: fileSize || 0 });
        } else if (type === 'clear') {
            setFileInfo({ fileName: null, fileSize: 0 });
        }
    };

    const handleClearAll = () => {
        console.log("HOME: Clear All clicked - clearing input section");
        if (inputSectionRef.current) {
            inputSectionRef.current.clearAll();
        }
        setFileInfo({ fileName: null, fileSize: 0 });
    };

    // Mock data for the table
    const columns = [
        {
            field: 'property',
            headerName: 'Property',
            flex: 1,
            editable: false,
        },
        {
            field: 'value',
            headerName: 'Value',
            flex: 1,
            editable: true,
        },
        {
            field: 'comment',
            headerName: 'Comment',
            flex: 2,
            editable: true,
        },
    ];

    const rows = [
        { id: 1, property: 'Server Name', value: 'prod-server-01', comment: 'Main production server' },
        { id: 2, property: 'Port', value: '8080', comment: 'Application port' },
        { id: 3, property: 'SSL Enabled', value: 'true', comment: 'SSL/TLS encryption enabled' },
        { id: 4, property: 'Timeout', value: '30s', comment: 'Connection timeout setting' },
        { id: 5, property: 'Max Connections', value: '100', comment: 'Maximum concurrent connections' },
    ];

    console.log("HOME: rendering with inputData:", inputData, "fileInfo:", fileInfo);

    return (
        <TabContext value={value}>
            <TabList onChange={handleChange} sx={{
                backgroundColor: 'white',
            }}>
                <Tab label="CERTIFICATES" value="1" />
                {isSuperuser ? <Tab label="SETTINGS" value="2" /> : null}
            </TabList>
            <TabPanel value="1" sx={{ padding: 0 }}>
                <SnackbarProvider
                    maxSnack={3}
                    autoHideDuration={5000}
                    anchorOrigin={{vertical: 'bottom', horizontal: 'center'}}
                >
                    <Box sx={{
                        padding: '10px',
                        display: 'flex',
                        gap: 2,
                        height: '80vh',
                    }}>
                        {/* Left side: Input Section + Table */}
                        <Box sx={{
                            flex: 1,
                            display: 'flex',
                            flexDirection: 'column',
                            gap: 2,
                        }}>
                            {/* Input Section */}
                            <InputSection 
                                ref={inputSectionRef}
                                onDataReceived={handleDataReceived} 
                            />
                            
                            {/* Table */}
                            <Box sx={{
                                flex: 1,
                                backgroundColor: 'white',
                                borderRadius: '10px',
                                padding: '10px',
                                boxShadow: 2,
                            }}>
                                <DataGrid
                                    rows={rows}
                                    columns={columns}
                                    pageSize={10}
                                    rowsPerPageOptions={[10]}
                                    checkboxSelection
                                    disableSelectionOnClick
                                    sx={{
                                        '& .MuiDataGrid-columnHeader': {
                                            backgroundColor: 'lightgray',
                                            fontWeight: 'bold',
                                        },
                                        border: 'none',
                                    }}
                                />
                            </Box>
                        </Box>

                        {/* Right side: Options Panel (full height) */}
                        <OptionsPanel 
                            onClearAll={handleClearAll} 
                            fileInfo={fileInfo}
                        />
                    </Box>
                </SnackbarProvider>
            </TabPanel>
            {isSuperuser && (
                <TabPanel value="2">
                    <SnackbarProvider
                        maxSnack={3}
                        autoHideDuration={5000}
                        anchorOrigin={{vertical: 'bottom', horizontal: 'center'}}
                    >
                        <Settings/>
                    </SnackbarProvider>
                </TabPanel>
            )}
        </TabContext>
    );
}

export default Home;