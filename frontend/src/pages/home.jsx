import Box from "@mui/material/Box";
import Typography from "@mui/material/Typography";

function Home() {
    return (
        <Box sx={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            minHeight: 'calc(100vh - 120px)', // Account for header and footer
            p: 3,
        }}>
            <Typography 
                variant="h2" 
                component="h1" 
                sx={{
                    color: 'rgb(1, 111, 157)',
                    fontWeight: 'bold',
                    textAlign: 'center',
                    mb: 2,
                }}
            >
                Certificate Tools
            </Typography>
            <Typography 
                variant="h6" 
                component="p" 
                sx={{
                    color: '#666',
                    textAlign: 'center',
                    maxWidth: '600px',
                }}
            >
                A comprehensive tool for managing SSL certificates, monitoring expiration dates, 
                and automating certificate-related tasks.
            </Typography>
        </Box>
    );
}

export default Home;