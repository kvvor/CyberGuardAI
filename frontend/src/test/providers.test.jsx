import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {ProviderSettings} from '../components/ProviderSettings';
import AttachmentReputation from '../components/AttachmentReputation';
import i18n from '../i18n';

it.each(['openai','virustotal'])('saves, tests and removes %s credentials through authenticated API',async provider=>{
 let saved=false;
 const fetch=vi.spyOn(window,'fetch').mockImplementation((url,options)=>{
  if(options.method==='POST'&&!url.endsWith('/test')) saved=true;
  if(options.method==='DELETE') saved=false;
  return Promise.resolve(new Response(options.method==='DELETE'?null:JSON.stringify(url.endsWith('/test')?{success:false,failure_code:'authentication_failed'}:{provider,model:'gpt-4.1-mini',enabled:true,has_credential:saved}),{status:options.method==='DELETE'?204:200}));
 });
 render(<ProviderSettings provider={provider}/>);
 const input=await screen.findByLabelText('API key (leave blank to keep saved key)');
 fireEvent.change(input,{target:{value:'synthetic-secret'}});
 fireEvent.click(screen.getByRole('button',{name:'Save configuration'}));
 await screen.findByText('Credential configured');
 expect(screen.getByLabelText('API key (leave blank to keep saved key)')).toHaveValue('');
 const call=fetch.mock.calls.find(([,o])=>o.method==='POST');
 expect(JSON.parse(call[1].body)).toMatchObject({provider,api_key:'synthetic-secret',enabled:true});
 expect(call[1].credentials).toBe('include');
 expect(localStorage.getItem('api_key')).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:'Test connection'}));
 expect(await screen.findByRole('alert')).toHaveTextContent('Invalid provider credentials');
 fireEvent.click(screen.getByRole('button',{name:'Remove credentials'}));
 await screen.findByText('Not configured — add a key in Settings');
 await waitFor(()=>expect(fetch.mock.calls.some(([,o])=>o.method==='DELETE')).toBe(true));
});

it.each(['en','ru','kk'])('renders attachment reputation in %s without a safety claim',async lang=>{
 await i18n.changeLanguage(lang);
 render(<AttachmentReputation report={{email:{attachments:[{filename:'report.pdf',sha256:'abc',size:12}]},attachment_reputation:[{sha256:'abc',status:'not_found'}]}}/>);
 expect(screen.getByText(i18n.t('not_found'))).toBeInTheDocument();
 expect(screen.getByText(i18n.t('vtUnknown'))).toBeInTheDocument();
 await i18n.changeLanguage('en');
});
