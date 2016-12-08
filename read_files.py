def parse_client_file(file_name):
    temp_arguments = []
    client_arguments = {}

    with open(file_name, 'r') as file:
        for line in file:
            temp_arguments.append(line)

    client_arguments['server_ip'] = temp_arguments[0].replace("\n", "")
    client_arguments['server_port_number'] = temp_arguments[1].replace("\n", "")
    client_arguments['client_port_number'] = temp_arguments[2].replace("\n", "")
    client_arguments['file_name'] = temp_arguments[3].replace("\n", "")
    client_arguments['receiveing_sliding_window_size'] = temp_arguments[4].replace("\n", "")
    return client_arguments


def parse_server_file(file_name):
    temp_arguments = []
    server_arguments = {}
    
    with open(file_name, 'r') as file:
        for line in file:
            temp_arguments.append(line)

    server_arguments['server_port_number'] = temp_arguments[0].replace("\n", "")
    server_arguments['sending_sliding_window_size'] = temp_arguments[1].replace("\n", "")
    server_arguments['random_generate_seed_value'] = temp_arguments[2].replace("\n", "")
    server_arguments['loss_probability'] = temp_arguments[3].replace("\n", "")
    return server_arguments


