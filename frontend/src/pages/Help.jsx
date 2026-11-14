import {useTranslation} from "react-i18next";
import {helpContent} from "../i18n/help";
export default function Help(){const {i18n,t}=useTranslation();return <section className="panel help"><h2>{t("help")}</h2>{(helpContent[i18n.language]||helpContent.en).map(([title,text])=><details key={title}><summary>{title}</summary><p>{text}</p></details>)}</section>;}
