import os
import json
import time
from bs4 import BeautifulSoup
import streamlit as st
from dotenv import load_dotenv
from prompts import *
from helpers import *


# Configuration and environment setup
load_dotenv()
serper_api_key = os.getenv("SERP_API_KEY")
openai_api_key = os.getenv("OPENAI_API_KEY")
brwoserless_api_key = os.getenv("BROWSERLESS_API_KEY")
# os.environ["LANGCHAIN_TRACING_V2"] = "true"
# os.environ["LANGCHAIN_ENDPOINT"] = "https://api.smith.langchain.com"
# os.environ["LANGCHAIN_PROJECT"] = "SplunkGPT"
# os.environ["LANGCHAIN_API_KEY"] = ""


# Path to the state JSON file
STATE_FILE = os.path.join(os.getcwd(), "state.json")

def load_state():
    """Load the current state from the JSON file."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as file:
            return json.load(file)
    # return a default state if no file exists
    return {
        'initial_setup_done': False,
        'user_has_responded': False,
        'spl_command_updated': False,
        'prompted_for_input': False,
        'spl_processed': False,
        'display_spl': False,
        'spl_command': "",
        'updated_spl_command': "",
    }

def save_state(state):
    """Save the current state to the JSON file."""
    with open(STATE_FILE, 'w') as file:
        json.dump(state, file)

# Path to the local JSON file
TASK_LIST_FILE = os.path.join(os.getcwd(), "task_list.json")

def update_task_list(task, task_list_json):
    # st.markdown(f"### Before removal: Number of tasks in task_list_json = **{len(task_list_json)}**")
    # st.markdown(f"### Attempting to remove task with id = **{task['id']}** and description = **{task['description']}**")
    task_list_json.remove(task)
    # st.markdown(f"### After removal: Number of tasks in task_list_json = **{len(task_list_json)}**")
    with open(TASK_LIST_FILE, 'w') as file:
        json.dump(task_list_json, file)
        
def load_task_list():
    """Load the task list from the JSON file."""
    if os.path.exists(TASK_LIST_FILE):
        with open(TASK_LIST_FILE, 'r') as file:
            return json.load(file)
    return []

def save_task_list(task_list_json):
    """Save the task list to the JSON file."""
    with open(TASK_LIST_FILE, 'w') as file:
        json.dump(task_list_json, file)

# Streamlit UI setup
st.title("⛓🦖 **SplunkGPT** 🧩⛓")
local = st.sidebar.checkbox('Search Local Vector Datastore ', value=False)
user_input = st.text_input("Write a Splunk Query to detect <insert below> in my Windows Domain:")

def perform_research():
    prefix = "Local Search " if local else "Internet Search "
    agent_kwargs = {"system_message": research_system_template,}
    research_chain = initialize_agent(research_tools,llm, agent=AgentType.OPENAI_FUNCTIONS, verbose=False, agent_kwargs=agent_kwargs)
    research_question = f"{prefix} for current detection procedures that detects {user_input} using Windows Security logs"
    print(f"==== DEBUG === research_question= {research_question}")
    return research_chain({"input": research_question})['output']

def gather_splunk_info():
    search_query = "| tstats values(source) as source by index"
    data = run_splunk_search(search_query)
    data = """
    index [main], 
    source [WinEventLog:Application, WinEventLog:Security, WinEventLog:Setup, WinEventLog:System],
    sourcetype [WinEventLog]
    """
    return [result for result in data]

def gather_schema_info(content):
    schema = {}
    event_id_chain = LLMChain(llm=llm, prompt=event_id_prompt, verbose=False)
    items = event_id_chain.run(content)[1:-1].split(', ')
    for event_code in items:
        st.write(f"<span style='color: blue;'>Gathering Splunk fields for EventCode </span>{event_code} <span style='color: blue;'>...</span>", unsafe_allow_html=True)
        search_query = f'search index="main" EventCode={event_code} | fieldsummary |table field '
        field_data = run_splunk_search(search_query)
        all_fields = [field_name for fields in field_data if isinstance(fields, dict) for field_name in fields.values()]
        schema[event_code] = all_fields
    return schema

def enhance_tasks(objective, actual_content, splunk_info, schema):
    initial_response = start_chain.run(objective)
    detial_response = detial_chain.predict(objective=objective,task_list_json=initial_response,detection_procedures=actual_content, splunk_info=splunk_info, schema=schema)
    context_response = tasks_context_chain.predict(objective=objective,task_list_json=detial_response, detection_procedures=actual_content)
    return json.loads(context_response)["tasks"]

def main():
    current_state = load_state()  # Load the current state from the file

    if user_input:
        objective = f"Build a Splunk SPL Query to detect {user_input} in a windows environment"

        if not current_state['initial_setup_done']:
            st.markdown("<span style='color: blue;'>Researching...</span>", unsafe_allow_html=True)
            actual_content = perform_research()
            st.markdown("<span style='color: yellow; font-size: 18px;'> Finished Research ...</span>", unsafe_allow_html=True)
            
            st.markdown("<span style='color: blue;'>Gathering Splunk Indexes and Sourcetypes...</span>", unsafe_allow_html=True)
            splunk_info = gather_splunk_info()
            schema = gather_schema_info(actual_content)
            st.markdown("<span style='color: yellow; font-size: 18px;'> Completed gathering Splunk information ...</span>", unsafe_allow_html=True)
            
            st.markdown("<span style='color: blue;'>Adding Details and Context to Each Task...</span>", unsafe_allow_html=True)
            task_list_json = enhance_tasks(objective, actual_content, splunk_info, schema)
            save_task_list(task_list_json)
            
            current_state['initial_setup_done'] = True
            save_state(current_state)
        
        # MAIN LOOP
        st.markdown("<span style='color: yellow; font-size: 18px;'> Entering Task Execution Loop ...</span>", unsafe_allow_html=True)
        
        spl_command = current_state['spl_command']
        updated_spl_command = current_state['updated_spl_command']
        
        task_list_json = load_task_list()  # Load the tasks from the file

        while task_list_json:  # Keep looping until there are no more tasks
            task = task_list_json[0]  # Process the first task in the list
            chosen_agent = task["agent"]

            if chosen_agent == "splunk_executor_agent":
                spl_command = current_state['spl_command']

                # If SPL hasn't been displayed, show it
                if not current_state['display_spl']:
                    st.markdown("<span style='color: yellow; font-size: 18px;'> Current SPL:</span>", unsafe_allow_html=True)
                    st.write(current_state['spl_command'])
                    current_state['display_spl'] = True
                    current_state['spl_command'] = spl_command
                    save_state(current_state) 
                                      
                # If not prompted before, show the input box

                if not current_state['prompted_for_input']:
                    updated_spl_command = st.text_input("Please make changes to the command:", spl_command)
                    time.sleep(30)
                    current_state['prompted_for_input'] = True
                    current_state['updated_spl_command'] = updated_spl_command
                    save_state(current_state)

                
                if current_state['spl_command'] != current_state['updated_spl_command']:   
                    current_state['spl_command_updated'] = True
                    save_state(current_state)
                    
                if current_state['spl_command_updated']:
                    #st.markdown(f"<span style='color: yellow; font-size: 18px;'> DEBUG spl_command_updated {current_state['updated_spl_command']} DEGBU ...</span>", unsafe_allow_html=True)
                    splunk_results = handle_splunk_executor_agent(task, current_state['updated_spl_command'])    
                    st.markdown("<span style='color: yellow; font-size: 18px;'> Splunk Results</span>", unsafe_allow_html=True)
                    st.write(splunk_results)
                    st.markdown("<span style='color: yellow; font-size: 18px;'> Splunk Result Analysis</span>", unsafe_allow_html=True)
                    st.write(handle_spl_results_agent(objective, updated_spl_command, splunk_results))

                    update_task_list(task, task_list_json)
                    task_list_json = load_task_list()


            elif chosen_agent == "spl_writer_agent":
                spl_command = handle_spl_writer_agent(task, objective,schema,splunk_info)
                #print(f"=== DEBUG ===\n\nspl_writer_agent={spl_command}\n\n=== DEBUG ===")
                update_task_list(task, task_list_json)
                task_list_json = load_task_list()            
            elif chosen_agent == 'spl_filter_agent':
                st.markdown("<span style='color: blue;'>Entering spl_filter_agent logic...</span>", unsafe_allow_html=True)
                spl_command = handle_spl_filter_agent(task, objective, spl_command)
                #print(f"=== DEBUG ===\n\nspl_filter_agent={spl_command}\n\n=== DEBUG ===")
                update_task_list(task, task_list_json)
                task_list_json = load_task_list()            
            elif chosen_agent == "spl_statistical_analysis_agent":
                spl_command = handle_spl_statistical_analysis_agent(task, objective, spl_command)
                #print(f"=== DEBUG ===\n\nspl_statistical_analysis_agent={spl_command}\n\n=== DEBUG ===")
                update_task_list(task, task_list_json)
                task_list_json = load_task_list()
            elif chosen_agent == "spl_refactor_agent":
                spl_command = handle_spl_refactor_agent(task, objective, spl_command, splunk_info, schema)
                #print(f"=== DEBUG ===\n\nspl_refactor_agent={spl_command}\n\n=== DEBUG ===")
                update_task_list(task, task_list_json)
                task_list_json = load_task_list()
            else:
                #st.markdown(f"<span style='color: red;'>Unknown agent: {chosen_agent}</span>", unsafe_allow_html=True)
                update_task_list(task, task_list_json)
                task_list_json = load_task_list()


if __name__ == "__main__":
    main()
