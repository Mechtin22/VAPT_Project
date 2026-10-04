import {
    BrowserRouter,
    Routes,
    Route
} from "react-router-dom";

import Dashboard from "./pages/Dashboard";
import Assessments from "./pages/Assessments";
import Findings from "./pages/Findings";
import Evidence from "./pages/Evidence";
import Retesting from "./pages/Retesting";
import Reports from "./pages/Reports";
import HttpRequests from "./httpRequests";

import Sidebar from "./components/Sidebar";
import Navbar from "./components/Navbar";

function App() {

    return (

        <BrowserRouter>

            <div className="app">

                <Sidebar />

                <div className="main">

                    <Navbar />

                    <div className="content">

                        <Routes>

                            <Route
                                path="/"
                                element={
                                    <Dashboard />
                                }
                            />

                            <Route
                                path="/assessments"
                                element={
                                    <Assessments />
                                }
                            />

                            <Route
                                path="/findings"
                                element={
                                    <Findings />
                                }
                            />

                            <Route
                                path="/http-requests"
                                element={
                                    <HttpRequests />
                                }
                            />

                            <Route
                                path="/evidence"
                                element={
                                    <Evidence />
                                }
                            />

                            <Route
                                path="/retesting"
                                element={
                                    <Retesting />
                                }
                            />

                            <Route
                                path="/reports"
                                element={
                                    <Reports />
                                }
                            />

                        </Routes>

                    </div>

                </div>

            </div>

        </BrowserRouter>

    );
}


export default App;