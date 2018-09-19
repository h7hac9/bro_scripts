load base/frameworks/files
@load base/protocols/http

module RESPONSE;

export {
    redef record HTTP::Info += {
        req_data:  string &log &optional;
        file_data: string &log &optional;
    };

    global file_name: string;
}


event log_post_data(f: fa_file, data:string)
{
   for(cid in f$conns)
   {
            local c: connection = f$conns[cid];
            if( ! c$http?$file_data )
                       c$http$file_data = "";
                if(c?$http && c$http?$current_entity && c$http$current_entity?$filename)
                {
                    c$http$file_data = c$http$file_data + data;
                }
                else{
                    if( ! c$http?$req_data )
                        c$http$req_data = "";
                    c$http$req_data = c$http$req_data + data;
                }
             if ( |c$http$file_data| > 1024)
               {
                    c$http$file_data = c$http$file_data[0:1024] + "...";
                    Files::remove_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=log_post_data]);
               }
    }
}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
{
    if( is_orig && c?$http && c$http?$method && c$http$method == "POST")
    {
        Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT,[$stream_event=log_post_data]);
    }
}
