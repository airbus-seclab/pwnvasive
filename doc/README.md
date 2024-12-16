## Documentation

### add
Add an instance of an object 
```
add <obj> [val='']                         
```

### auto
Modify the state of a handler to automate tasks.
```
auto  [handler=None] [on='on']             
```

### cat
Display the contents of a node file
```
cat <selector> <pth>                       
```

### cnx
Create a session with a node
```
cnx  [selector=None]                       
```

### compute_network
Graphically represent our playing area 
```
compute_network                            
```

### config
Add/modify/delete attributes in the database
```
config  [key=None] [op=None] [val=None]    
```

### del
Delete the instance of an object
```
del <obj> <selector>                       
```

### disconnect
End a session 
```
disconnect  [selector=None]                
```

### eval
Evaluate a function
```
eval <cmd>                                 
```

### exit
Exit the prompt
```
exit                                       
```

### extract_networks
Try to find new networks/new nodes 
```
extract_networks  [selector=None]          
```

### flush
Delete all instances of an object
```
flush <obj> [selector=None]                
```

### id
Identify the machine's operating system
```
id  [selector=None]                        
```

### info
Display an abstract of a node's information
```
info <selector>                            
```

### ls
List objects and instances of an object
```
ls  [obj=None] [selector=None]             
```

### monitor           
Display the actions that pwnvasive performs internally
```
monitor <what> [onoff='on']
```

### pdb
Debug pwnvasive
```
pdb                                        
```

### quit
Exit the prompt
```
quit
```

### run
Run a command on a node
```
run <selector> <cmd>                       
```

### save
Save the database
```
save  [fname=None]                         
```

### service
View / Start / Stop a service
```
service  [svc=None] [startstop='start']    
```

### show
Display the details of an object instance
```
show <obj> [selector=None]                 
```

### tasks
View current tasks
```
tasks                                      
```

### update
Modify the variables of an object instance
```
update <obj> <selector> <vals>  
```