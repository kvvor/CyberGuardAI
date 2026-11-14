import {createContext,useContext,useEffect,useState} from "react";
import {api,setCSRF} from "../services/api";
const Context=createContext(null);
export const useAuth=()=>useContext(Context);
export function AuthProvider({children}){
 const [state,setState]=useState({loading:true});
 const accept=data=>{setCSRF(data.csrf_token);setState({user:data.user,setup:data.password_change_required});};
 const refresh=()=>{setState({loading:true});api("/auth/me").then(accept).catch(e=>setState(e.code==="PASSWORD_CHANGE_REQUIRED"?{setup:true}:e.code==="UNAUTHENTICATED"?{}:{error:e.code}));};
 useEffect(()=>{refresh();const listener=e=>setState(e.detail==="PASSWORD_CHANGE_REQUIRED"?{setup:true}:{});window.addEventListener("auth-state",listener);return()=>window.removeEventListener("auth-state",listener);},[]);
 async function logout(){await api("/auth/logout",{method:"POST"});setCSRF("");setState({});}
 return <Context.Provider value={{...state,accept,refresh,logout,clear:()=>{setCSRF("");setState({});}}}>{children}</Context.Provider>;
}
