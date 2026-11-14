import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "../contexts/Auth";
import { Application } from "../App";
import i18n from "../i18n";
const response=(data,status=200)=>new Response(JSON.stringify(data),{status});
function setup({enabled=true,error,offline=false}={}){
 const fetch=vi.spyOn(window,"fetch").mockImplementation((url,options)=>{
  if(url.endsWith("/auth/me"))return Promise.resolve(response({error:{code:"UNAUTHENTICATED"}},401));
  if(url.endsWith("/config/public"))return Promise.resolve(response({public_signup:enabled}));
  if(url.endsWith("/auth/register"))return offline?Promise.reject(new TypeError("offline")):Promise.resolve(error?response({error:{code:error}},error==="RATE_LIMITED"?429:400):response({code:"REGISTRATION_ACCEPTED"},202));
  if(url.endsWith("/auth/login"))return Promise.resolve(response({user:{id:"u",email:"new@example.com",display_name:"New user"},password_change_required:false,csrf_token:"test"}));
  return Promise.resolve(response({total_analyses:0,recent_analyses:[]}));
 });return fetch;
}
function open(path="/register"){render(<MemoryRouter initialEntries={[path]}><AuthProvider><Application/></AuthProvider></MemoryRouter>);}
async function fill(){await screen.findByLabelText("Display name");for(const [label,value] of [["Display name","New user"],["Email address","new@example.com"],["Password","a secure new passphrase"],["Confirm password","a secure new passphrase"]])fireEvent.change(screen.getByLabelText(label),{target:{value}});}
beforeEach(async()=>{await i18n.changeLanguage("en");});
describe("website registration",()=>{
 it("submits exact payload without CSRF and redirects to login with a private acknowledgment",async()=>{const fetch=setup();open();await fill();fireEvent.click(screen.getByRole("button",{name:"Create Account"}));expect(await screen.findByText(/Registration request accepted/)).toBeInTheDocument();const call=fetch.mock.calls.find(([url])=>url.endsWith("/register"));expect(JSON.parse(call[1].body)).toEqual({display_name:"New user",email:"new@example.com",password:"a secure new passphrase",confirm_password:"a secure new passphrase"});expect(call[1].headers["X-CSRF-Token"]).toBeUndefined();expect(screen.getByLabelText("Password")).toHaveValue("");expect(screen.getByRole("button",{name:"Sign in"})).toBeInTheDocument();});
 it("allows login after accepted registration",async()=>{const fetch=setup();open();await fill();fireEvent.click(screen.getByRole("button",{name:"Create Account"}));await screen.findByRole("button",{name:"Sign in"});fireEvent.change(screen.getByLabelText("Email address"),{target:{value:"new@example.com"}});fireEvent.change(screen.getByLabelText("Password"),{target:{value:"a secure new passphrase"}});fireEvent.click(screen.getByRole("button",{name:"Sign in"}));await waitFor(()=>expect(fetch.mock.calls.some(([url])=>url.endsWith("/auth/login"))).toBe(true));});
 it("hides registration when disabled and blocks direct access",async()=>{setup({enabled:false});open();expect(await screen.findByText(/registration is currently disabled/)).toBeInTheDocument();expect(screen.queryByLabelText("Display name")).toBeNull();fireEvent.click(screen.getByRole("link",{name:"Back to sign in"}));expect(await screen.findByRole("button",{name:"Sign in"})).toBeInTheDocument();expect(screen.queryByRole("link",{name:"Create Account"})).toBeNull();});
 it("shows login registration link when enabled",async()=>{setup();open("/login");expect(await screen.findByRole("link",{name:"Create Account"})).toHaveAttribute("href","/register");});
 it("rejects mismatched confirmation without submitting",async()=>{const fetch=setup();open();await fill();fireEvent.change(screen.getByLabelText("Confirm password"),{target:{value:"different passphrase"}});fireEvent.click(screen.getByRole("button",{name:"Create Account"}));expect(await screen.findByRole("alert")).toHaveTextContent("Passwords do not match");expect(fetch.mock.calls.some(([url])=>url.endsWith("/register"))).toBe(false);});
 it("validates UTF-8 byte limits and password length",async()=>{const fetch=setup();open();await fill();fireEvent.change(screen.getByLabelText("Display name"),{target:{value:"Қ".repeat(101)}});fireEvent.click(screen.getByRole("button",{name:"Create Account"}));expect(await screen.findByRole("alert")).toHaveTextContent("200 UTF-8 bytes");fireEvent.change(screen.getByLabelText("Display name"),{target:{value:"Name"}});fireEvent.change(screen.getByLabelText("Password"),{target:{value:"short"}});fireEvent.click(screen.getByRole("button",{name:"Create Account"}));expect(screen.getByRole("alert")).toHaveTextContent("at least 12");expect(fetch.mock.calls.some(([url])=>url.endsWith("/register"))).toBe(false);});
 it.each(["RATE_LIMITED","INVALID_REGISTRATION_INPUT","REGISTRATION_DISABLED"])("handles %s from backend",async error=>{setup({error});open();await fill();fireEvent.click(screen.getByRole("button",{name:"Create Account"}));expect(await screen.findByText(i18n.t(error))).toBeInTheDocument();});
 it("handles network failure",async()=>{setup({offline:true});open();await fill();fireEvent.click(screen.getByRole("button",{name:"Create Account"}));expect(await screen.findByRole("alert")).toHaveTextContent("Cannot reach the backend");});
 it.each(["ru","kk"])("localizes registration in %s",async lang=>{setup();await i18n.changeLanguage(lang);open();expect(await screen.findByLabelText(i18n.t("display_name"))).toBeInTheDocument();expect(screen.getByRole("button",{name:i18n.t("register")})).toBeInTheDocument();});
});
