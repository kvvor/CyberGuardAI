import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent} from '@testing-library/react';
import EvidenceReport from '../components/EvidenceReport';

const base={report:{scoring_version:'3.0.0',email:{subject:'Message',attachments:[]},iocs:[],evidence:[{id:'sender-1',value:'sender@example.test'}],authentication:[]},ai_execution:{status:'completed'}};
it('renders model verdict and grounded evidence without a numerical score',()=>{
 const analysis={...base,ai_assessment:{proposed_verdict:'suspicious',severity:'medium',confidence:'low',supporting_evidence_ids:['sender-1'],explanations:{en:'Verify the sender.'},recommendations:{en:'Use a known contact.'}}};
 render(<EvidenceReport analysis={analysis} onExport={vi.fn()} onDelete={vi.fn()}/>);
 expect(screen.getByText('Verify the sender.')).toBeInTheDocument();
 expect(screen.getByText(/sender@example.test/)).toBeInTheDocument();
 expect(screen.queryByText('/ 100')).not.toBeInTheDocument();
});
it('labels failure as incomplete instead of presenting an AI verdict',()=>{
 render(<EvidenceReport analysis={{...base,ai_execution:{status:'timeout'}}}/>);
 expect(screen.getByText('Assessment incomplete — no AI verdict')).toBeInTheDocument();
});
it('filters and paginates IOCs without active links',()=>{
 const analysis={...base,report:{...base.report,iocs:Array.from({length:45},(_,i)=>({type:'url',resource_category:'actionable_hyperlink',normalized_value:`https://example.test/${i}`,defanged_value:`hxxps://example[.]test/${i}`}))}};
 render(<EvidenceReport analysis={analysis}/>);
 expect(screen.getAllByRole('row',{hidden:true})).toHaveLength(20);
 fireEvent.click(screen.getByText('Next page'));
 expect(screen.getByText('hxxps://example[.]test/20')).toBeInTheDocument();
 fireEvent.change(screen.getByLabelText('Search evidence'),{target:{value:'/44'}});
 expect(screen.getAllByRole('row',{hidden:true})).toHaveLength(1);
 expect(screen.queryByRole('link')).not.toBeInTheDocument();
});
