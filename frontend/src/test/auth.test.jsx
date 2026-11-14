import {describe,it,expect,vi} from "vitest";
import {render,screen,fireEvent,waitFor} from "@testing-library/react";
import {MemoryRouter} from "react-router-dom";
import {AuthProvider} from "../contexts/Auth";
import {Application} from "../App";
const auth={user:{id:"u",email:"analyst@example.com",display_name:"Analyst"},csrf_token:"csrf",password_change_required:false};
const response=(data,status=200)=>new Response(JSON.stringify(data),{status});
function app(path){return render(<MemoryRouter initialEntries={[path]}><AuthProvider><Application/></AuthProvider></MemoryRouter>);}
describe("authentication flows",()=>{
 it("redirects unauthenticated protected requests to login",async()=>{vi.spyOn(window,"fetch").mockResolvedValue(response({error:{code:"UNAUTHENTICATED"}},401));app("/settings");expect(await screen.findByRole("button",{name:"Sign in"})).toBeInTheDocument();});
 it("blocks invalid login form submission",async()=>{const fetch=vi.spyOn(window,"fetch").mockResolvedValue(response({error:{code:"UNAUTHENTICATED"}},401));app("/login");const submit=await screen.findByRole("button",{name:"Sign in"});fireEvent.click(submit);expect(fetch).toHaveBeenCalledTimes(1);expect(screen.getByLabelText("Email address")).toBeInvalid();});
 it("recovers setup session and activates it",async()=>{const fetch=vi.spyOn(window,"fetch").mockImplementation(url=>url.endsWith("/auth/me")?Promise.resolve(response({error:{code:"PASSWORD_CHANGE_REQUIRED"}},403)):url.endsWith("/activate-account")?Promise.resolve(response(auth)):Promise.resolve(response({total_analyses:0,activity_series:[],recent_analyses:[]})));app("/settings");expect(await screen.findByRole("button",{name:"Activate account"})).toBeInTheDocument();for(const label of ["New password","Confirm password"])fireEvent.change(screen.getByLabelText(label),{target:{value:"a secure password"}});fireEvent.click(screen.getByRole("button",{name:"Activate account"}));await waitFor(()=>expect(fetch.mock.calls.some(([url])=>url.endsWith("/activate-account"))).toBe(true));});
 it("logs out and returns to login",async()=>{const fetch=vi.spyOn(window,"fetch").mockImplementation(url=>Promise.resolve(url.endsWith("/logout")?new Response(null,{status:204}):response(auth)));app("/settings");fireEvent.click(await screen.findByRole("button",{name:"Sign out"}));expect(await screen.findByRole("button",{name:"Sign in"})).toBeInTheDocument();expect(fetch.mock.calls.find(([url])=>url.endsWith("/logout"))[1].headers["X-CSRF-Token"]).toBe("csrf");});
 it("shows retry on backend outage during session recovery",async()=>{vi.spyOn(window,"fetch").mockRejectedValue(new TypeError("offline"));app("/dashboard");expect(await screen.findByRole("alert")).toHaveTextContent("Cannot reach the backend");expect(screen.getByRole("button",{name:"Retry"})).toBeInTheDocument();});
});
