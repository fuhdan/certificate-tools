import {useState, useRef} from "react";
import TabContext from "@mui/lab/TabContext";
import TabList from "@mui/lab/TabList";
import Tab from "@mui/material/Tab";
import TabPanel from "@mui/lab/TabPanel";
import {SnackbarProvider} from "notistack";
import Box from "@mui/material/Box";
import {DataGrid} from "@mui/x-data-grid";
import Typography from "@mui/material/Typography";
import Settings from "../components/settings.jsx";
import OptionsPanel from "../components/optionsPanel.jsx";
import InputSection from "../components/inputSection.jsx";

function Home({ isSuperuser }) {
    const [value, setValue] = useState('1');
    const [inputData, setInputData] = useState('');
    const [fileInfo, setFileInfo] = useState({ fileName: null, fileSize: 0 });
    const [certificateData, setCertificateData] = useState(null);
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
            setCertificateData(null);
        }
    };

    const handleCertificateData = (certData) => {
        console.log("HOME: Certificate data received:", certData);
        setCertificateData(certData);
    };

    const handleClearAll = () => {
        console.log("HOME: Clear All clicked - clearing input section");
        if (inputSectionRef.current) {
            inputSectionRef.current.clearAll();
        }
        setFileInfo({ fileName: null, fileSize: 0 });
        setCertificateData(null);
    };

    // Generate table data based on certificate information
    const getTableData = () => {
        if (!certificateData || !certificateData.certificate) {
            // Default mock data when no certificate is loaded
            return [
                { id: 1, property: 'File Status', value: 'No file loaded', comment: 'Upload a certificate file to see details' },
            ];
        }

        // Convert certificate properties to table rows
        const rows = [];
        let id = 1;

        // File information
        rows.push({
            id: id++,
            property: 'Filename',
            value: certificateData.filename || 'Unknown',
            comment: 'Original uploaded filename'
        });

        rows.push({
            id: id++,
            property: 'File Type',
            value: certificateData.filetype || 'Unknown',
            comment: 'Type of certificate file'
        });

        rows.push({
            id: id++,
            property: 'File Format',
            value: certificateData.fileformat || 'Unknown',
            comment: 'Encoding format of the file'
        });

        // Certificate properties
        Object.entries(certificateData.certificate).forEach(([key, value]) => {
            rows.push({
                id: id++,
                property: key,
                value: String(value),
                comment: getCertificatePropertyComment(key)
            });
        });

        return rows;
    };

    const getCertificatePropertyComment = (property) => {
        const comments = {
            'Version': 'X.509 certificate version',
            'Serial Number': 'Unique identifier for this certificate',
            'Subject.Common Name': 'Primary domain or entity name',
            'Subject.Organization': 'Organization name',
            'Subject.Country': 'Country code',
            'Issuer.Common Name': 'Certificate Authority name',
            'Public Key Algorithm': 'Type of public key cryptography',
            'Key Size': 'Size of the public key in bits',
            'Signature Algorithm': 'Algorithm used to sign the certificate',
            'Not Valid Before': 'Certificate validity start date',
            'Not Valid After': 'Certificate expiration date',
            'Subject Alternative Names': 'Additional domain names covered',
        };
        
        return comments[property] || 'Certificate property';
    };

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
            flex: 1.5,
            editable: false,
            renderCell: (params) => (
                <Typography 
                    variant="body2" 
                    sx={{ 
                        wordBreak: 'break-word',
                        whiteSpace: 'normal',
                        lineHeight: 1.2,
                        py: 1
                    }}
                >
                    {params.value}
                </Typography>
            ),
        },
        {
            field: 'comment',
            headerName: 'Comment',
            flex: 2,
            editable: false,
            renderCell: (params) => (
                <Typography 
                    variant="body2" 
                    sx={{ 
                        color: 'rgba(0, 0, 0, 0.6)',
                        wordBreak: 'break-word',
                        whiteSpace: 'normal',
                        lineHeight: 1.2,
                        py: 1
                    }}
                >
                    {params.value}
                </Typography>
            ),
        },
    ];

    const rows = getTableData();

    console.log("HOME: rendering with certificateData:", certificateData);

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
                                onCertificateData={handleCertificateData}
                            />
                            
                            {/* Table */}
                            <Box sx={{
                                flex: 1,
                                backgroundColor: 'white',
                                borderRadius: '10px',
                                padding: '10px',
                                boxShadow: 2,
                            }}>
                                <Typography variant="h6" sx={{
                                    fontWeight: 'bold',
                                    color: 'rgb(1, 111, 157)',
                                    marginBottom: '10px',
                                }}>
                                    Certificate Details
                                </Typography>
                                <DataGrid
                                    rows={rows}
                                    columns={columns}
                                    pageSize={25}
                                    rowsPerPageOptions={[25, 50, 100]}
                                    disableSelectionOnClick
                                    getRowHeight={() => 'auto'}
                                    sx={{
                                        '& .MuiDataGrid-columnHeader': {
                                            backgroundColor: 'lightgray',
                                            fontWeight: 'bold',
                                        },
                                        '& .MuiDataGrid-cell': {
                                            display: 'flex',
                                            alignItems: 'center',
                                            lineHeight: 'unset !important',
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