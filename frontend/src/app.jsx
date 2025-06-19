import './styles/app.css'
import Header from "./components/header.jsx";
import Footer from "./components/footer.jsx";
import Box from "@mui/material/Box"
import Home from "./pages/home.jsx";
import {useEffect, useState} from "react";

/**
 * Simplified App component without Azure AD for development
 * This bypasses the crypto issues in non-HTTPS environments
 */
function App() {
    const [roleDataJson, setRoleDataJson] = useState({
        isSuperuser: false,
        isAuthorized: false,
    });

    useEffect(() => {
        console.debug("APP", "running mode", import.meta.env.MODE);
        console.debug("APP", "serving base url", import.meta.env.BASE_URL);
        console.debug("APP", "running in server", import.meta.env.SSR);
        console.debug("APP", "redirect uri", import.meta.env.VITE_REACT_APP_REDIRECT_URI);
    },[]);

    // Mock callback for header component
    const handleCallback = (parentCallback) => {
        console.debug("APP", "roleDataJson", roleDataJson);
        console.debug("APP", "parentCallback", parentCallback);
        if (roleDataJson.isSuperuser !== parentCallback.isSuperuser ||
            roleDataJson.isAuthorized !== parentCallback.isAuthorized) {
            setRoleDataJson(parentCallback);
        }
    };

    return (
        <>
            <Box sx={{
                display: 'flex',
                flexDirection: 'column',
                minHeight: '100vh',
            }}>
                <Header
                    parentCallback={handleCallback}
                />
                <Box sx={{
                    flex: 1,
                    paddingBottom: '60px', // Space for fixed footer
                }}>
                    <Home/>
                </Box>
                <Footer value="home" />
            </Box>
        </>
    );
}

export default App;