import {useEffect, useMemo, useState} from "react";
import Box from "@mui/material/Box";
import {TextField} from "@mui/material";
import Button from '@mui/material/Button';
import qs from "qs";
import AxiosInterceptor from "../hooks/axiosInstance.jsx";
import {useSnackbar} from 'notistack';
import xtype from 'xtypejs';

const SmtpServer = () => {
    console.info("SS", "Entering SmtpServer");

    //#region variables

    const [loading, setLoading] = useState(false);
    const [data, setData] = useState([]);
    const [rows, setRows] = useState([]);
    const [record, setRecord] = useState({});
    const [refreshSmtpServer, setRefreshSmtpServer] = useState(false);
    const { enqueueSnackbar} = useSnackbar();

    //#endregion

    console.debug("SS", "loading", loading);

    //#region axios

    const axiosInstance = useMemo(() => {
        return new AxiosInterceptor({
            tokenUsername: import.meta.env.VITE_REACT_APP_API_USER,
            tokenPassword: import.meta.env.VITE_REACT_APP_API_PASSWORD,
            baseURL: import.meta.env.VITE_REACT_APP_API_URL,
        })
    }, []);

    //#endregion

    //#region API functions

    useEffect(() => {
            if (Object.keys(record).length > 0) {
                const patchRecord = async () => {
                    console.info("SS", "Patching SMTP Server");
                    setLoading(true);
                    await axiosInstance.patch("/smtp_server/?"+qs.stringify(record))
                        .then((response) => {
                            console.debug("SS", "patching_smtp_server_api_response", response);
                            enqueueSnackbar("SMTP Server changed.", {variant: "success"});
                            setRefreshSmtpServer(!refreshSmtpServer);
                        });
                }
                patchRecord()
                    .finally(() => setLoading(false))
                    .catch(error => {
                        console.error("SS", "Patching SMTP Server failed", error);
                        enqueueSnackbar("Changing SMTP Server failed: " + error.response?.data?.detail || error.message, {variant: "error", autoHideDuration: 20000});
                    });
            }
        },
        [record, axiosInstance, enqueueSnackbar, refreshSmtpServer],
    );

    useEffect(() => {
            const getSmtpServer = async () => {
                console.info("SS", "Getting SMTP Server");
                setLoading(true);
                // Mock data for demo - replace with actual API call
                const mockData = [
                    [1, "smtp.example.com", 587, "noreply@example.com"]
                ];
                setData(mockData);
                console.debug("SS", "getting_smtp_server_mock_response", mockData);
            }
            getSmtpServer()
                .finally(() => setLoading(false))
                .catch(error => {
                    console.log("SS", "Getting SMTP Server failed", error);
                })
        },
        [refreshSmtpServer],
    );

    //#endregion

    //#region row mapping

    useEffect(() => {
            if (data.length > 0 && xtype(data) !== "multi_char_string") {
                const mappingRows = async () => {
                    setLoading(true);
                    let mapped_rows = data.map(data => ({
                        server_address: data[1],
                        server_port: data[2],
                        server_from: data[3],
                    }));
                    setRows(mapped_rows);
                    console.debug("SS", "smtp_server_mapped_rows", mapped_rows);
                };
                mappingRows()
                    .finally(() => setLoading(false))
                    .catch(error => {
                        console.error("SS", "Mapping SMTP Server Rows failed", error)
                    });
            }
        },
        [data],
    );

    //#endregion

    //#region get input

    const handleSubmit = (event) => {
        event.preventDefault();
        console.debug("SS", "handleSubmit", "event", event);
        const stringAPI = {
            server_address: event.target.server_address.value,
            server_port: event.target.server_port.value,
            server_from: event.target.server_from.value,
        };
        setRecord(stringAPI);
        enqueueSnackbar("SMTP Server settings saved (Demo mode)", {variant: "success"});
    };

    //#endregion

    return (
        <Box>
            <Box sx={{
                backgroundColor: 'lightgray',
                color: 'black',
                fontStyle: 'normal',
                margin: '10px',
                borderRadius: '10px',
                justifySelf: 'center',
                width: '100%',
                maxWidth: '500px',
            }}>
                <form onSubmit={handleSubmit}>
                    {rows.length > 0 ? (
                        <Box sx={{
                            display: 'flex',
                            flexDirection: 'column',
                            alignItems: 'center',
                            textAlign: 'center',
                            p: 2,
                            '& .MuiTextField-root': {
                                m: 1,
                                borderRadius: 2,
                            },
                        }}>
                            {"Server Address"}
                            <TextField name="server_address"
                                       placeholder={rows[0].server_address}
                                       variant="outlined"
                                       sx={{
                                           backgroundColor: 'white',
                                           width: '90%',
                                       }}
                            />
                            {"Server Port"}
                            <TextField name="server_port"
                                       placeholder={rows[0].server_port.toString()}
                                       variant="outlined"
                                       sx={{
                                           backgroundColor: 'white',
                                           width: '90%',
                                       }}
                            />
                            {"Server From"}
                            <TextField name="server_from"
                                       placeholder={rows[0].server_from}
                                       variant="outlined"
                                       sx={{
                                           backgroundColor: 'white',
                                           width: '90%',
                                       }}
                            />
                            <Button variant="contained" type="submit" sx={{
                                backgroundColor: 'rgb(1, 111, 157)',
                                color: 'white',
                                m: '10px',
                                borderRadius: '5px',
                            }}>
                                {"SUBMIT"}
                            </Button>
                        </Box>
                    ) : (
                        <Box sx={{ p: 2, textAlign: 'center' }}>
                            Loading SMTP settings...
                        </Box>
                    )}
                </form>
            </Box>
        </Box>
    )
}

const Settings = () => {
    console.info("S", "Entering Settings");

    return (
        <Box sx={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            width: '100%',
            p: 2,
        }}>
            <Box sx={{
                display: 'flex',
                flexDirection: 'column',
                width: '100%',
                maxWidth: '600px',
            }}>
                <Box sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    padding: '5px',
                    margin: '5px',
                    boxShadow: 5,
                }}>
                    <Box sx={{
                        textAlign: 'center',
                        fontSize: 'large',
                        fontWeight: 'bold',
                        mb: 2,
                    }}>
                        SMTP Server
                    </Box>
                    <SmtpServer />
                </Box>
            </Box>
        </Box>
    )
}

export default Settings;