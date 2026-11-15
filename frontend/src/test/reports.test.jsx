import {describe,it,expect,vi} from "vitest";
import {render,screen,fireEvent,waitFor} from "@testing-library/react";
import {MemoryRouter,Routes,Route} from "react-router-dom";
import "../i18n";
import Details from "../pages/Details";
import {History} from "../pages/Dashboard";
const report={id:"a",mode:"demo",status:"partial",created_at:"2026-01-01T00:00:00Z",explanations:{en:"Synthetic explanation"},recommendations:{en:"Verify independently"},report:{verdict:"phishing",risk_level:"high",risk_score:75,email:{subject:"<script>alert(1)</script>",sender:"sender@example.com",attachments:[]},ai_status:"predefined_demo",iocs:[{type:"url",value:"https://suspicious.invalid",defanged_value:"hxxps://suspicious[.]invalid",source:"body"}],mitre_mappings:[{technique_id:"T1566.002",technique_name:"Spearphishing Link",mapping_status:"suspected",evidence_ids:["f1"]}],indicators:[],limitations:["Missing headers"]}};
describe("reports and history",()=>{
 it("shows loading while analysis is pending",()=>{vi.spyOn(window,"fetch").mockImplementation(()=>new Promise(()=>{}));render(<MemoryRouter initialEntries={["/analyses/a"]}><Routes><Route path="/analyses/:id" element={<Details/>}/></Routes></MemoryRouter>);expect(screen.getByRole("status")).toHaveTextContent("Loading");});
});
