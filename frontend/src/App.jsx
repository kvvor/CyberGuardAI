import {Component,useState,lazy,Suspense} from "react";

import {BrowserRouter,Routes,Route,Navigate,Outlet,NavLink,Link,useLocation} from "react-router-dom";
import {useTranslation} from "react-i18next";
import {MotionConfig,motion} from "motion/react";
import {ShieldCheck,LayoutDashboard,ScanLine,History as HistoryIcon,Settings,BookOpen,Menu,LogOut} from "lucide-react";
import "./i18n";
import "./i18n/extra";
import "./styles.css";
import {AuthProvider,useAuth} from "./contexts/Auth";
import {ErrorMessage,Loading,Preferences} from "./components/common";
import AuthPage,{PasswordForm} from "./pages/Auth";
import Analyzer from "./pages/Analyzer";
const Dashboard=lazy(()=>import("./pages/Dashboard"));
const History=lazy(()=>import("./pages/Dashboard").then(m=>({default:m.History})));
import Help from "./pages/Help";
import Details from "./pages/Details";
const nav=[["dashboard",LayoutDashboard],["analyze",ScanLine],["history",HistoryIcon],["help",BookOpen],["settings",Settings]];
function SettingsPage(){const {t}=useTranslation();const auth=useAuth();return <><section className="panel"><h2>{t("profile")}</h2><p>{auth.user?.display_name}</p><p>{auth.user?.email}</p></section><section className="panel"><h2>{t("security")}</h2><PasswordForm/></section><section className="panel"><h2>{t("theme")} / {t("language")}</h2><Preferences/></section></>;}
function Shell(){const {t}=useTranslation();const auth=useAuth();const location=useLocation();const [collapsed,setCollapsed]=useState(false);const [error,setError]=useState("");return <div className={`shell ${collapsed?"collapsed":""}`}><aside><Link to="/dashboard" className="brand"><ShieldCheck/><span>CyberGuard <b>AI</b></span></Link><nav>{nav.map(([key,Icon])=><NavLink key={key} aria-label={t(key)} to={`/${key}`}><Icon size={20}/><span>{t(key)}</span></NavLink>)}</nav><div className="account"><span>{auth.user?.display_name}</span><small>{auth.user?.email}</small><button aria-label={t("logout")} onClick={async()=>{try{await auth.logout();}catch(e){setError(e.code);}}}><LogOut size={16}/><span>{t("logout")}</span></button></div></aside><div className="workspace"><header><button aria-label={t("menu")} aria-expanded={!collapsed} onClick={()=>setCollapsed(!collapsed)}><Menu/></button><h1>{t(location.pathname.split("/")[1],{defaultValue:t("analyze")})}</h1><Preferences/></header><main className="content"><ErrorMessage code={error}/><motion.div key={location.pathname} initial={{opacity:0,y:5}} animate={{opacity:1,y:0}} transition={{duration:.15}}><Outlet/></motion.div></main></div></div>;}
function Protected(){const auth=useAuth();return auth.setup?<Navigate to="/activate-account" replace/>:auth.user?<Shell/>:<Navigate to="/login" replace/>;}
export function Application(){const auth=useAuth();const {t}=useTranslation();if(auth.loading)return <Loading/>;if(auth.error)return <main className="auth"><ErrorMessage code={auth.error}/><button onClick={auth.refresh}>{t("retry")}</button></main>;return <Routes><Route path="/login" element={<AuthPage/>}/><Route path="/activate-account" element={<AuthPage activation/>}/><Route element={<Protected/>}><Route path="/dashboard" element={<Dashboard/>}/><Route path="/analyze" element={<Analyzer/>}/><Route path="/analyses/:id" element={<Details/>}/><Route path="/history" element={<History/>}/><Route path="/settings" element={<SettingsPage/>}/><Route path="/help" element={<Help/>}/></Route><Route path="/" element={<Navigate to="/dashboard" replace/>}/><Route path="*" element={<main className="auth"><h1>{t("notFound")}</h1><Link to="/dashboard">{t("dashboard")}</Link></main>}/></Routes>;}
class Boundary extends Component{state={failed:false};static getDerivedStateFromError(){return {failed:true};}render(){return this.state.failed?<main role="alert">CyberGuard AI — <button onClick={()=>window.location.reload()}>↻</button></main>:this.props.children;}}
export default function App(){return (<Boundary><MotionConfig reducedMotion="user"><BrowserRouter><AuthProvider><Suspense fallback={<Loading/>}><Application/></Suspense></AuthProvider></BrowserRouter></MotionConfig></Boundary>);}