--  Copyright Robert Bosch GmbH, 2012.
--  Bosch Security Systems B.V.
--  BU Communication Systems - Breda, The Netherlands
--
--  Project             :   OCA
--  Module              :   Tools
--  Creation Date       :   19 Sep 2012
--  First Author        :   Marcel Versteeg
--
--  Description         :   Wireshark Packet dissector for OCP.1
--
--  Copy this file to 'Personal Plugins' as found in About->Folders
--  http://www.wireshark.org/docs/wsug_html_chunked/wsluarm.html
--  http://www.lua.org/manual/5.1/


-----------------------------------------------------------------------
-- BASIC CONVERSION ARRAYS
-----------------------------------------------------------------------

-- array to convert message type numbers to strings
local msgTypeToString = {
    [0x0] = "Command",
    [0x1] = "CommandResponseRequired",
    [0x2] = "Notification",
    [0x3] = "Response",
    [0x4] = "KeepAlive"
}

-- array to convert booleans to Yes/No strings
local boolToYesNoString = {
    [0] = "No",
    [1] = "Yes"
}

-- array to convert booleans to On/Off strings
local boolToOnOffString = {
    [0] = "Off",
    [1] = "On"
}


-----------------------------------------------------------------------
-- TABLES FOR STORING THE FIELD DEFINITIONS, KNOWN OBJECT NUMBER
-- DISSECTORS AND MESSAGE TYPE DISSECTORS
-- These tables are needed to limit the number of local variables, as there
-- is a maximum of 200 local variables in the main scope.
-- The fields are stored by their name as a key in the table and can
-- be referenced likewise.
-- The message type dissectors are stored by the message type as a key
-- in the table.
-- The fixed object dissectors are stored by their object number as a key
-- in the table.
-----------------------------------------------------------------------

local fieldDefs = {
}

local msgTypeDissector = {
}

local fixedObjectDissector = {
}


-----------------------------------------------------------------------
-- VARIABLES FOR TRACKING OF COMMANDS AND THEIR RESPONSES
-----------------------------------------------------------------------

local handles = {
}


-----------------------------------------------------------------------
-- BASIC OCP.1 PROTOCOL AND MESSAGE FIELD DEFINITIONS
-----------------------------------------------------------------------

-- create the OCP.1 protocol general message fields
fieldDefs['syncValue'] = ProtoField.uint8("ocp.1.sync", "OCP.1 Synchronization Value", base.HEX)
fieldDefs['pduHeader'] = ProtoField.bytes("ocp.1.header", "OCP.1 PDU Header")
fieldDefs['pduProtocolVersion'] = ProtoField.uint16("ocp.1.version", "Protocol Version", base.DEC)
fieldDefs['pduMessageSize'] = ProtoField.uint32("ocp.1.msgsize", "Message Size", base.DEC)
fieldDefs['pduMessageType'] = ProtoField.uint8("ocp.1.msgtype", "Message Type", base.DEC, msgTypeToString)
fieldDefs['pduMessageCount'] = ProtoField.uint16("ocp.1.msgcount", "Message Count", base.DEC)
fieldDefs['pduData'] = ProtoField.bytes("ocp.1.data", "OCP.1 Message Data")


-----------------------------------------------------------------------
-- OCP.1 PROTOCOL DISSECTOR
-----------------------------------------------------------------------

-----------------------------------------------------------------------
-- Function to check whether a packet can be of the OCP.1 protocol
-----------------------------------------------------------------------

local function IsOcp1(buf)
    -- check if the message is longer than the header size (10 bytes)
    if buf:len() <= 10
    then
        return false
    end

    -- check if the message starts with the synchronization value
    if buf(0, 1):uint() ~= 0x3B
    then
        return false
    end

    -- check if the protocol version is 1
    if buf(1, 2):uint() ~= 1
    then
        return false
    end

    -- get the message size and check if the message is long enough
    local msgSize = buf(3, 4):uint()
    if buf:len() < (msgSize + 1)
    then
        return false
    end

    -- get the message type and verify if it is in range
    if buf(7, 1):uint() > 4
    then
        return false
    end

    return true
end

-----------------------------------------------------------------------
-- Main OCP.1 protocol dissector
-----------------------------------------------------------------------

-- create the OCP.1 protocol
local ocp1 = Proto("ocp.1", "OCA Protocol for TCP/IP Networks")
ocp1.fields = { fieldDefs['syncValue'],
                fieldDefs['pduHeader'],
                fieldDefs['pduProtocolVersion'],
                fieldDefs['pduMessageSize'],
                fieldDefs['pduMessageType'],
                fieldDefs['pduMessageCount'],
                fieldDefs['pduData'] }

-- main protocol dissector function
function ocp1.dissector(buf, pkt, root)
    --
    -- perform some basic checks to see if this is actually OCP.1 protocol
    --

    if IsOcp1(buf)
    then
        --
        -- start filling the protocol information, the message is probably an OCP.1 message
        --

        -- set the protocol in the packet list
        pkt.cols.protocol = ocp1.name

        -- construct the basic information in the packet list
        local myInfo = "Src: " .. pkt.src_port .. " > Dst: " .. pkt.dst_port

        -- create a new sub tree for the dissected message
        local subtree = root:add(ocp1, buf())

        -- create the strings for source and destination
        local srcString = tostring(pkt.src) .. '_' .. pkt.src_port
        local dstString = tostring(pkt.dst) .. '_' .. pkt.dst_port

        -- add all the messages that are in the packet
        local startPos = 0
        while startPos < buf:len()
        do
            -- find the next synchronization value
            while (startPos < buf:len()) and (buf(startPos, 1):uint() ~= 0x3B)
            do
                startPos = startPos + 1
            end

            if startPos < buf:len()
            then
                -- construct the message type in the packet information
                local msgSize = buf(startPos + 3, 4):uint()
                local msgType = buf(startPos + 7, 1):uint()
                myInfo = myInfo .. ", " .. msgTypeToString[msgType]

                -- add the message header information
                subtree:add(fieldDefs['syncValue'], buf(startPos, 1))
                local header = subtree:add(fieldDefs['pduHeader'], buf(startPos + 1, 9))
                header:add(fieldDefs['pduProtocolVersion'], buf(startPos + 1, 2))
                header:add(fieldDefs['pduMessageSize'], buf(startPos + 3, 4))
                header:add(fieldDefs['pduMessageType'], buf(startPos + 7, 1))
                header:add(fieldDefs['pduMessageCount'], buf(startPos + 8, 2))

                -- find a dissector for the message type and execute it if found
                local dissector = msgTypeDissector[msgType]
                if dissector ~= nil
                then
                    local data = subtree:add(fieldDefs['pduData'], buf(startPos + 10, msgSize - 9))
                    dissector(buf(startPos + 10, msgSize - 9):tvb(), msgSize - 9, srcString, dstString, buf(startPos + 8, 2):uint(), data)
                end

                startPos = startPos + msgSize + 1
            end
        end

        -- set the basic information in the packet list
        pkt.cols.info = myInfo
    else
        return 0
    end
end

-- register dissector to be able to "Decode As..."
local tcp_dissector_table = DissectorTable.get("tcp.port")
local udp_dissector_table = DissectorTable.get("udp.port")
local ssl_dissector_table = DissectorTable.get("ssl.port")
tcp_dissector_table:add(90000, ocp1)
udp_dissector_table:add(90000, ocp1)
ssl_dissector_table:add(90000, ocp1)

-----------------------------------------------------------------------
-- Heuristic OCP.1 dissector (determines whether the protocol is OCP.1)
-----------------------------------------------------------------------

-- main heuristic dissector function
local function ocp1Heuristics(buf, pkt, root)
    if IsOcp1(buf)
    then
        -- set the conversation for this to automatically dissect this communication as OCP.1
        pkt.conversation = ocp1
        return true
    else
        return false
    end
end

-- register heuristic dissector function (only available from Wireshark 1.11, so use pcall to suppress errors)
pcall(function() ocp1:register_heuristic("tcp", ocp1Heuristics) end)
pcall(function() ocp1:register_heuristic("udp", ocp1Heuristics) end)


-----------------------------------------------------------------------
-- OCP.1 BASIC MESSAGE DISSECTORS
-----------------------------------------------------------------------

-- message fields for Command and CommandResponseRequired
fieldDefs['msgCommand'] = ProtoField.bytes("ocp.1.command", "Command")
fieldDefs['msgCommandSize'] = ProtoField.uint32("ocp.1.command.size", "Command Size", base.DEC)
fieldDefs['msgCommandHandle'] = ProtoField.uint32("ocp.1.command.handle", "Handle", base.DEC)
fieldDefs['msgCommandTargetONo'] = ProtoField.uint32("ocp.1.command.target", "Target Object Number", base.DEC)
fieldDefs['msgCommandMethodID'] = ProtoField.bytes("ocp.1.command.method", "Method ID")
fieldDefs['msgCommandParameters'] = ProtoField.bytes("ocp.1.command.params", "Command Parameters")
table.insert(ocp1.fields, fieldDefs['msgCommand'])
table.insert(ocp1.fields, fieldDefs['msgCommandSize'])
table.insert(ocp1.fields, fieldDefs['msgCommandHandle'])
table.insert(ocp1.fields, fieldDefs['msgCommandTargetONo'])
table.insert(ocp1.fields, fieldDefs['msgCommandMethodID'])
table.insert(ocp1.fields, fieldDefs['msgCommandParameters'])

-- helper dissector for Command and CommandResponseRequired
local function OcaCommandDissector(buf, length, srcString, dstString, msgCount, subtree, expectResponse)
    local startPos = 0
    for msg = 1, msgCount, 1
    do
        -- get the command size
        local commandSize = buf(startPos, 4):uint()

        local commandTree = subtree:add(fieldDefs['msgCommand'], buf(startPos, commandSize));
        commandTree:set_text("Command " .. msg)
        commandTree:add(fieldDefs['msgCommandSize'], buf(startPos, 4));
        local handle = buf(startPos + 4, 4):uint()
        commandTree:add(fieldDefs['msgCommandHandle'], buf(startPos + 4, 4));
        local targetONo = buf(startPos + 8, 4):uint()
        OcaONo(buf(startPos + 8):tvb(), fieldDefs['msgCommandTargetONo'], commandTree);
        local methodIDSize = OcaMethodID(buf(startPos + 12):tvb(), fieldDefs['msgCommandMethodID'], commandTree)
        local parameterSize = commandSize - (12 + methodIDSize)
        OcaMessageParameters(buf(startPos + 12 + methodIDSize):tvb(), fieldDefs['msgCommandParameters'], parameterSize, commandTree)

        -- find a dissector for the target object number and execute it if found
        local dissector = fixedObjectDissector[targetONo]
        local responseDissector = nil
        if dissector ~= nil
        then
            responseDissector = dissector(buf(startPos + 12, 2):uint(),
                                          buf(startPos + 14, 2):uint(),
                                          buf(startPos + 12 + methodIDSize, 1):uint(),
                                          buf(startPos + 12 + methodIDSize + 1):tvb(),
                                          commandTree)
        else
            -- if the definition level of the method id is 1, the called method is a method from OcaRoot
            -- so we can call the dissector for this class
            if buf(startPos + 12, 2):uint() == 1
            then
                responseDissector = OcaRoot(buf(startPos + 12, 2):uint(),
                                            buf(startPos + 14, 2):uint(),
                                            buf(startPos + 12 + methodIDSize, 1):uint(),
                                            buf(startPos + 12 + methodIDSize + 1):tvb(),
                                            commandTree)
            end
        end

        -- if there is a response to be expected, register the dissector for the response
        if (expectResponse ~= 0) and (responseDissector ~= nil)
        then
            if handles[dstString] == nil
            then
                -- add the destination to the handles list, so we can register the handles
                -- of the commands
                handles[dstString] = { }
            end
            handles[dstString]["h" .. tostring(handle)] = responseDissector
        end

        startPos = startPos + commandSize
    end
end

-- dissector for Command
local function OcaCommand(buf, length, srcString, dstString, msgCount, subtree)
    OcaCommandDissector(buf, length, srcString, dstString, msgCount, subtree, 0)
end

-- dissector for CommandResponseRequired
local function OcaCommandResponseRequired(buf, length, srcString, dstString, msgCount, subtree)
    OcaCommandDissector(buf, length, srcString, dstString, msgCount, subtree, 1)
end

-- message fields for Notification
fieldDefs['msgNotification'] = ProtoField.bytes("ocp.1.notification", "Notification")
fieldDefs['msgNotificationSize'] = ProtoField.uint32("ocp.1.notification.size", "Notification Size", base.DEC)
fieldDefs['msgNotificationTargetONo'] = ProtoField.uint32("ocp.1.notification.target", "Target Object Number", base.DEC)
fieldDefs['msgNotificationMethodID'] = ProtoField.bytes("ocp.1.notification.method", "Method ID")
fieldDefs['msgNotificationParameters'] = ProtoField.bytes("ocp.1.notification.params", "Notification Parameters")
fieldDefs['msgNotificationContext'] = ProtoField.bytes("ocp.1.notification.context", "Context")
fieldDefs['msgNotificationEvent'] = ProtoField.bytes("ocp.1.notification.event", "Event")
table.insert(ocp1.fields, fieldDefs['msgNotification'])
table.insert(ocp1.fields, fieldDefs['msgNotificationSize'])
table.insert(ocp1.fields, fieldDefs['msgNotificationTargetONo'])
table.insert(ocp1.fields, fieldDefs['msgNotificationMethodID'])
table.insert(ocp1.fields, fieldDefs['msgNotificationParameters'])
table.insert(ocp1.fields, fieldDefs['msgNotificationContext'])
table.insert(ocp1.fields, fieldDefs['msgNotificationEvent'])

-- dissector for Notification
local function OcaNotification(buf, length, srcString, dstString, msgCount, subtree)
    local startPos = 0
    for msg = 1, msgCount, 1
    do
        -- get the nofication size
        local notificationSize = buf(startPos, 4):uint()

        local notificationTree = subtree:add(fieldDefs['msgNotification'], buf(startPos, notificationSize));
        notificationTree:set_text("Notification " .. msg)
        notificationTree:add(fieldDefs['msgNotificationSize'], buf(startPos, 4));
        OcaONo(buf(startPos + 4):tvb(), fieldDefs['msgNotificationTargetONo'], notificationTree);
        local methodIDSize = OcaMethodID(buf(startPos + 8):tvb(), fieldDefs['msgNotificationMethodID'], notificationTree)
        local parameterSize = notificationSize - (8 + methodIDSize)
        OcaMessageParameters(buf(startPos + 8 + methodIDSize):tvb(), fieldDefs['msgNotificationParameters'], parameterSize, notificationTree)
        local contextSize = OcaBlob(buf(startPos + 8 + methodIDSize + 1):tvb(), fieldDefs['msgNotificationContext'], notificationTree)
        OcaEvent(buf(startPos + 8 + methodIDSize + 1 + contextSize):tvb(), fieldDefs['msgNotificationEvent'], notificationTree)
    end
end

-- array to convert status code numbers to strings
local ocaStatusToString = {
    [ 0] = "OK",
    [ 1] = "Protocol Version Error",
    [ 2] = "Device Error",
    [ 3] = "Locked",
    [ 4] = "Bad Format",
    [ 5] = "Bad Object Number",
    [ 6] = "Parameter Error",
    [ 7] = "Parameter Out Of Range",
    [ 8] = "Not Implemented",
    [ 9] = "Invalid Request",
    [10] = "Processing Failed",
    [11] = "Bad Method",
    [12] = "Partially Succeeded",
    [13] = "Timeout",
    [14] = "Buffer Overflow"
}

-- message fields for Response
fieldDefs['msgResponse'] = ProtoField.bytes("ocp.1.response", "Response")
fieldDefs['msgResponseSize'] = ProtoField.uint32("ocp.1.response.size", "Response Size", base.DEC)
fieldDefs['msgResponseHandle'] = ProtoField.uint32("ocp.1.response.handle", "Handle", base.DEC)
fieldDefs['msgResponseStatus'] = ProtoField.uint32("ocp.1.response.status", "Status", base.DEC, ocaStatusToString)
fieldDefs['msgResponseParameters'] = ProtoField.bytes("ocp.1.response.params", "Response Parameters")
table.insert(ocp1.fields, fieldDefs['msgResponse'])
table.insert(ocp1.fields, fieldDefs['msgResponseSize'])
table.insert(ocp1.fields, fieldDefs['msgResponseHandle'])
table.insert(ocp1.fields, fieldDefs['msgResponseStatus'])
table.insert(ocp1.fields, fieldDefs['msgResponseParameters'])

-- dissector for Response
local function OcaResponse(buf, length, srcString, dstString, msgCount, subtree)
    local startPos = 0
    for msg = 1, msgCount, 1
    do
        -- get the response size
        local responseSize = buf(startPos, 4):uint()

        local responseTree = subtree:add(fieldDefs['msgResponse'], buf(startPos, responseSize));
        responseTree:set_text("Response " .. msg)
        responseTree:add(fieldDefs['msgResponseSize'], buf(startPos, 4));
        local handle = buf(startPos + 4, 4):uint()
        responseTree:add(fieldDefs['msgResponseHandle'], buf(startPos + 4, 4));
        responseTree:add(fieldDefs['msgResponseStatus'], buf(startPos + 8, 1));
        local parameterSize = responseSize - 9
        OcaMessageParameters(buf(startPos + 9):tvb(), fieldDefs['msgResponseParameters'], parameterSize, responseTree)

        -- check if there is dissector registered for the given handle
        if handles[srcString] ~= nil
        then
            local handleString = "h" .. tostring(handle)
            local dissector = handles[srcString][handleString]
            if dissector ~= nil
            then
                -- call the dissector (only if the command succeeded)
                local statuscode = buf(startPos + 8, 1):uint()
                if statuscode == 0
                then
                    dissector(buf(startPos + 9, 1):uint(),
                              buf(startPos + 10):tvb(),
                              responseTree)
                end
            else
                responseTree:add("Command information for this response not previously interpreted: unable to interpret response information")
            end
        else
            responseTree:add("Command information for this response not previously interpreted: unable to interpret response information")
        end

        startPos = startPos + responseSize
    end
end

-- message fields for KeepAlive
fieldDefs['msgKeepAliveHeartBeatTime'] = ProtoField.uint16("ocp.1.keepalive.hbtime", "Heart Beat Time", base.DEC)
table.insert(ocp1.fields, fieldDefs['msgKeepAliveHeartBeatTime'])

-- dissector for KeepAlive
function OcaKeepAlive(buf, length, srcString, dstString, msgCount, subtree)
    -- add the field information
    subtree:add(fieldDefs['msgKeepAliveHeartBeatTime'], buf(0, 2)):append_text(" seconds")
end

-- register the dissectors per message type
msgTypeDissector[0x0] = OcaCommand
msgTypeDissector[0x1] = OcaCommandResponseRequired
msgTypeDissector[0x2] = OcaNotification
msgTypeDissector[0x3] = OcaResponse
msgTypeDissector[0x4] = OcaKeepAlive


-----------------------------------------------------------------------
-- OCP.1 DATA TYPE DISSECTORS
-----------------------------------------------------------------------

-----------------------------------------------------------------------
-- Enumeration to string definitions
-----------------------------------------------------------------------

-- array to convert block type numbers to strings
local ocaBlockTypeToString = {
    [ 1] = "Root Block"
}

-- array to convert component numbers to strings
local ocaComponentToString = {
    [0] = "Bootloader"
}

-- array to convert reset cause code numbers to strings
local ocaDeviceManagerResetCauseToString = {
    [0] = "PowerOn",
    [1] = "InternalError",
    [2] = "Upgrade",
    [3] = "ExternalRequest"
}

-- array to convert device state code numbers to strings
local ocaDeviceManagerStateToString = {
    [0x0000] = "-",
    [0x0001] = "Operational",
    [0x0002] = "Disabled",
    [0x0003] = "Operational, Disabled",
    [0x0004] = "Error",
    [0x0005] = "Operational, Error",
    [0x0006] = "Disabled, Error",
    [0x0007] = "Operational, Disabled, Error",
    [0x0008] = "Initializing",
    [0x0009] = "Operational, Initializing",
    [0x000A] = "Disabled, Initializing",
    [0x000B] = "Operational, Disabled, Initializing",
    [0x000C] = "Error, Initializing",
    [0x000D] = "Operational, Error, Initializing",
    [0x000E] = "Disabled, Error, Initializing",
    [0x000F] = "Operational, Disabled, Error, Initializing",
    [0x0010] = "Updating",
    [0x0011] = "Operational, Updating",
    [0x0012] = "Disabled, Updating",
    [0x0013] = "Operational, Disabled, Updating",
    [0x0014] = "Error, Updating",
    [0x0015] = "Operational, Error, Updating",
    [0x0016] = "Disabled, Error, Updating",
    [0x0017] = "Operational, Disabled, Error, Updating",
    [0x0018] = "Initializing, Updating",
    [0x0019] = "Operational, Initializing, Updating",
    [0x001A] = "Disabled, Initializing, Updating",
    [0x001B] = "Operational, Disabled, Initializing, Updating",
    [0x001C] = "Error, Initializing, Updating",
    [0x001D] = "Operational, Error, Initializing, Updating",
    [0x001E] = "Disabled, Error, Initializing, Updating",
    [0x001F] = "Operational, Disabled, Error, Initializing, Updating"
}

-- array to convert library volume standard type id numbers to strings
local ocaLibVolStandardTypeIdToString = {
    [0] = "None",
    [1] = "ParamSet",
    [2] = "Patch",
    [3] = "Program"
}

-- array to convert media clock type numbers to strings
local ocaMediaClockTypeToString = {
    [0] = "None",
    [1] = "Internal",
    [2] = "Network",
    [3] = "External"
}

-- array to convert notification delivery mode numbers to strings
local ocaNotificationDeliveryModeToString = {
    [1] = "Reliable",
    [2] = "Fast"
}

-- array to convert object search result field map index numbers to strings
local ocaObjectSearchResultFlagsToString = {
    [0x0000] = "-",
    [0x0001] = "ONo",
    [0x0002] = "ClassIdentification",
    [0x0003] = "ONo, ClassIdentification",
    [0x0004] = "ContainerPath",
    [0x0005] = "ONo, ContainerPath",
    [0x0006] = "ClassIdentification, ContainerPath",
    [0x0007] = "ONo, ClassIdentification, ContainerPath",
    [0x0008] = "Role",
    [0x0009] = "ONo, Role",
    [0x000A] = "ClassIdentification, Role",
    [0x000B] = "ONo, ClassIdentification, Role",
    [0x000C] = "ContainerPath, Role",
    [0x000D] = "ONo, ContainerPath, Role",
    [0x000E] = "ClassIdentification, ContainerPath, Role",
    [0x000F] = "ONo, ClassIdentification, ContainerPath, Role",
    [0x0010] = "Label",
    [0x0011] = "ONo, Label",
    [0x0012] = "ClassIdentification, Label",
    [0x0013] = "ONo, ClassIdentification, Label",
    [0x0014] = "ContainerPath, Label",
    [0x0015] = "ONo, ContainerPath, Label",
    [0x0016] = "ClassIdentification, ContainerPath, Label",
    [0x0017] = "ONo, ClassIdentification, ContainerPath, Label",
    [0x0018] = "Role, Label",
    [0x0019] = "ONo, Role, Label",
    [0x001A] = "ClassIdentification, Role, Label",
    [0x001B] = "ONo, ClassIdentification, Role, Label",
    [0x001C] = "ContainerPath, Role, Label",
    [0x001D] = "ONo, ContainerPath, Role, Label",
    [0x001E] = "ClassIdentification, ContainerPath, Role, Label",
    [0x001F] = "ONo, ClassIdentification, ContainerPath, Role, Label"
}

-- array to convert port mode numbers to strings
local ocaPortModeToString = {
    [1] = "Input",
    [2] = "Output"
}

-- array to convert string comparison type numbers to strings
local ocaStringComparisonTypeToString = {
    [0] = "Exact",
    [1] = "Substring",
    [2] = "Contains"
}

-----------------------------------------------------------------------
-- OcaBlob
-----------------------------------------------------------------------

-- message fields for OcaBlob data type
fieldDefs['ocaBlobLength'] = ProtoField.uint16("ocp.1.blob.length", "Length", base.DEC)
fieldDefs['ocaBlobData'] = ProtoField.bytes("ocp.1.blob.data", "Data")
table.insert(ocp1.fields, fieldDefs['ocaBlobLength'])
table.insert(ocp1.fields, fieldDefs['ocaBlobData'])

-- dissector for OcaBlob data type
function OcaBlob(buf, protofield, subtree)
    local blobLength = buf(0, 2):uint()

    if subtree ~= nil
    then
        local blob = subtree:add(protofield, buf(0, 2 + blobLength))
        blob:add(fieldDefs['ocaBlobLength'], buf(0, 2))
        blob:add(fieldDefs['ocaBlobData'], buf(2, blobLength))
    end

    return (2 + blobLength)
end

-----------------------------------------------------------------------
-- OcaBlobFixedLen
-----------------------------------------------------------------------

-- dissector for OcaBlobFixedLen data type
function OcaBlobFixedLen(length, buf, protofield, subtree)
    if subtree ~= nil
    then
        subtree:add(protofield, buf(0, length))
    end

    return length
end

-----------------------------------------------------------------------
-- OcaBlockMember
-----------------------------------------------------------------------

-- message fields for OcaBlockMember data type
fieldDefs['ocaBlockMemberObjectIdentification'] = ProtoField.bytes("ocp.1.blkmem.objidf", "Object Identification")
fieldDefs['ocaBlockMemberContainerONo'] = ProtoField.uint32("ocp.1.blkmem.contono", "Container Object Number")
table.insert(ocp1.fields, fieldDefs['ocaBlockMemberObjectIdentification'])
table.insert(ocp1.fields, fieldDefs['ocaBlockMemberContainerONo'])

-- dissector for OcaBlockMember data type
function OcaBlockMember(buf, protofield, subtree)
    local objectIdentificationLength = OcaObjectIdentification(buf(0):tvb(), nil, nil)

    if subtree ~= nil
    then
        local blockMember = subtree:add(protofield, buf(0, objectIdentificationLength + 4))
        OcaObjectIdentification(buf(0):tvb(), fieldDefs['ocaBlockMemberObjectIdentification'], blockMember)
        OcaONo(buf(objectIdentificationLength):tvb(), fieldDefs['ocaBlockMemberContainerONo'], blockMember)
    end

    return (objectIdentificationLength + 4)
end

-----------------------------------------------------------------------
-- OcaClassID
-----------------------------------------------------------------------

-- message fields for OcaClassID data type
fieldDefs['ocaClassIDFieldCount'] = ProtoField.uint16("ocp.classid.fieldcnt", "Field Count", base.DEC)
fieldDefs['ocaClassIDFields'] = ProtoField.bytes("ocp.message.classid.fields", "Class ID")
table.insert(ocp1.fields, fieldDefs['ocaClassIDFieldCount'])
table.insert(ocp1.fields, fieldDefs['ocaClassIDFields'])

-- dissector for OcaClassID data type
function OcaClassID(buf, protofield, subtree)
    local length = buf(0, 2):uint()

    if subtree ~= nil
    then
        local classID = subtree:add(protofield, buf(0, 2 + (length * 2)))
        classID:add(fieldDefs['ocaClassIDFieldCount'], buf(0, 2))
        local fields = classID:add(fieldDefs['ocaClassIDFields'], buf(2, length * 2))
        local fieldsText = "Class ID: "
        local proprietaryFieldCount = 0;
        for v = 1, length, 1
        do
            local field = buf(v * 2, 2):uint();
            if (field ~= 0xffff)
            then
                if (proprietaryFieldCount == 1)
                then
                    fieldsText = fieldsText .. string.format("%02X", buf(v * 2 + 1, 1):uint()) .. ":"
                    proprietaryFieldCount = proprietaryFieldCount + 1
                elseif (proprietaryFieldCount == 2)
                then
                    fieldsText = fieldsText .. string.format("%02X", buf(v * 2, 1):uint()) .. ":" .. string.format("%02X", buf(v * 2 + 1, 1):uint()) .. " "
                    proprietaryFieldCount = proprietaryFieldCount + 1
                elseif (proprietaryFieldCount == 3)
                then
                    fieldsText = fieldsText .. field
                    proprietaryFieldCount = proprietaryFieldCount + 1
                elseif ((proprietaryFieldCount == 0) or (proprietaryFieldCount > 3))
                then
                    if (v > 1)
                    then
                        fieldsText = fieldsText .. "."
                    end
                    fieldsText = fieldsText .. field
                end
            else
                fieldsText = fieldsText .. ", proprietary extension by manf "
                proprietaryFieldCount = proprietaryFieldCount + 1;
            end
        end
        fields:set_text(fieldsText)
    end

    return (2 + (length * 2))
end

-----------------------------------------------------------------------
-- OcaClassIdentification
-----------------------------------------------------------------------

-- message fields for OcaClassIdentification data type
fieldDefs['ocaClassIdentificationClassID'] = ProtoField.bytes("ocp.1.classidf.classid", "Class ID")
fieldDefs['ocaClassIdentificationClassVersion'] = ProtoField.uint16("ocp.1.classidf.classvers", "Class Version", base.DEC)
table.insert(ocp1.fields, fieldDefs['ocaClassIdentificationClassID'])
table.insert(ocp1.fields, fieldDefs['ocaClassIdentificationClassVersion'])

-- dissector for OcaClassIdentification data type
function OcaClassIdentification(buf, protofield, subtree)
    local classIDLength = OcaClassID(buf(0):tvb(), nil, nil)

    if subtree ~= nil
    then
        local classIdentification = subtree:add(protofield, buf(0, classIDLength + 2))
        OcaClassID(buf(0):tvb(), fieldDefs['ocaClassIdentificationClassID'], classIdentification)
        classIdentification:add(fieldDefs['ocaClassIdentificationClassVersion'], buf(classIDLength, 2))
    end

    return (classIDLength + 2)
end

-----------------------------------------------------------------------
-- OcaEnumeration (pseudo type)
-----------------------------------------------------------------------

-- dissector for OcaEnumeration data type (8 bits)
function OcaEnumeration(buf, protofield, subtree)
    if subtree ~= nil
    then
        subtree:add(protofield, buf(0, 1))
    end

    return 1
end

-----------------------------------------------------------------------
-- OcaEvent
-----------------------------------------------------------------------

-- message fields for OcaEvent data type
fieldDefs['ocaEventEmitterONo'] = ProtoField.uint32("ocp.1.event.emitter", "Emitter Object Number", base.DEC)
fieldDefs['ocaEventEventID'] = ProtoField.bytes("ocp.1.event.eventid", "Event ID")
table.insert(ocp1.fields, fieldDefs['ocaEventEmitterONo'])
table.insert(ocp1.fields, fieldDefs['ocaEventEventID'])

-- dissector for OcaEvent data type
function OcaEvent(buf, protofield, subtree)
    local eventIDLength = OcaEventID(buf(4):tvb(), nil, nil)

    if subtree ~= nil
    then
        local event = subtree:add(protofield, buf(0, eventIDLength + 4))
        OcaONo(buf(0):tvb(), fieldDefs['ocaEventEmitterONo'], event);
        OcaEventID(buf(4):tvb(), fieldDefs['ocaEventEventID'], event);
    end

    return (4 + eventIDLength)
end

-----------------------------------------------------------------------
-- OcaEventID
-----------------------------------------------------------------------

-- message fields for OcaEventID data type
fieldDefs['ocaEventIDDefLevel'] = ProtoField.uint16("ocp.1.eventid.level", "Definition Level", base.DEC)
fieldDefs['ocaEventIDIndex'] = ProtoField.uint16("ocp.1.eventid.index", "Event Index", base.DEC)
table.insert(ocp1.fields, fieldDefs['ocaEventIDDefLevel'])
table.insert(ocp1.fields, fieldDefs['ocaEventIDIndex'])

-- dissector for OcaEventID data type
function OcaEventID(buf, protofield, subtree)
    if subtree ~= nil
    then
        local eventID = subtree:add(protofield, buf(0, 4))
        eventID:add(fieldDefs['ocaEventIDDefLevel'], buf(0, 2))
        eventID:add(fieldDefs['ocaEventIDIndex'], buf(2, 2))
    end

    return 4
end

-----------------------------------------------------------------------
-- OcaGlobalBlockTypeIdentifier
-----------------------------------------------------------------------

-- message fields for OcaGlobalBlockTypeIdentifier data type
fieldDefs['ocaGlobalBlockTypeIdentifierAuthority'] = ProtoField.bytes("ocp.1.gbtypeid.auth", "Authority")
fieldDefs['ocaGlobalBlockTypeIdentifierID'] = ProtoField.uint32("ocp.1.gbtypeid.id", "ID", base.DEC)
table.insert(ocp1.fields, fieldDefs['ocaGlobalBlockTypeIdentifierAuthority'])
table.insert(ocp1.fields, fieldDefs['ocaGlobalBlockTypeIdentifierID'])

-- dissector for OcaGlobalBlockTypeIdentifier data type
function OcaGlobalBlockTypeIdentifier(buf, protofield, subtree)
    local idLength = OcaOrganizationID(buf(0):tvb(), nil, nil)

    if subtree ~= nil
    then
        local globalBlockTypeIdentifier = subtree:add(protofield, buf(0, idLength + 4))
        OcaOrganizationID(buf(0):tvb(), fieldDefs['ocaGlobalBlockTypeIdentifierAuthority'], globalBlockTypeIdentifier);
        OcaUint32(buf(idLength, 4):tvb(), fieldDefs['ocaGlobalBlockTypeIdentifierID'], globalBlockTypeIdentifier)
    end

    return (idLength + 4)
end

-----------------------------------------------------------------------
-- OcaLibVolData_ParamSet
-----------------------------------------------------------------------

-- message fields for OcaLibVolData_ParamSet data type
fieldDefs['ocaLibVolData_ParamSetTargetBlockType'] = ProtoField.uint32("ocp.1.lvdata_ps.target", "Target Block Type", base.DEC, ocaBlockTypeToString)
fieldDefs['ocaLibVolData_ParamSetData'] = ProtoField.bytes("ocp.1.lvdata_ps.data", "Parameter Set Data")
table.insert(ocp1.fields, fieldDefs['ocaLibVolData_ParamSetTargetBlockType'])
table.insert(ocp1.fields, fieldDefs['ocaLibVolData_ParamSetData'])

-- dissector for OcaLibVolData_ParamSet data type
function OcaLibVolData_ParamSet(buf, protofield, subtree)
    local dataLength = OcaBlob(buf(4):tvb(), nil, nil)

    if subtree ~= nil
    then
        local libVolData_ParamSet = subtree:add(protofield, buf(0, 4 + dataLength))
        OcaONo(buf(0):tvb(), fieldDefs['ocaLibVolData_ParamSetTargetBlockType'], libVolData_ParamSet);
        OcaBlob(buf(4):tvb(), fieldDefs['ocaLibVolData_ParamSetData'], libVolData_ParamSet)
    end

    return (4 + dataLength)
end

-----------------------------------------------------------------------
-- OcaLibVolID
-----------------------------------------------------------------------

-- dissector for OcaLibVolID data type
function OcaLibVolID(buf, protofield, subtree)
    subtree:add(protofield, buf(0, 4))

    return 4
end

-----------------------------------------------------------------------
-- OcaLibVolIdentifier
-----------------------------------------------------------------------

-- message fields for OcaLibVolIdentifier data type
fieldDefs['ocaLibVolIdentifierLibrary'] = ProtoField.uint32("ocp.1.libvolid.lib", "Library", base.DEC)
fieldDefs['ocaLibVolIdentifierId'] = ProtoField.uint32("ocp.1.libvolid.id", "ID", base.DEC)
table.insert(ocp1.fields, fieldDefs['ocaLibVolIdentifierLibrary'])
table.insert(ocp1.fields, fieldDefs['ocaLibVolIdentifierId'])

-- dissector for OcaLibVolIdentifier data type
function OcaLibVolIdentifier(buf, protofield, subtree)
    if subtree ~= nil
    then
        local libVolIdentifier = subtree:add(protofield, buf(0, 8))
        OcaONo(buf(0):tvb(), fieldDefs['ocaLibVolIdentifierLibrary'], libVolIdentifier)
        OcaLibVolID(buf(4):tvb(), fieldDefs['ocaLibVolIdentifierId'], libVolIdentifier)
    end

    return 8
end

-----------------------------------------------------------------------
-- OcaLibVolType
-----------------------------------------------------------------------

-- message fields for OcaLibVolType data type
fieldDefs['ocaLibVolTypeAuthority'] = ProtoField.bytes("ocp.1.libvoltype.auth", "Authority")
fieldDefs['ocaLibVolTypeId'] = ProtoField.uint8("ocp.1.libvoltype.id", "ID", base.DEC, ocaLibVolStandardTypeIdToString)
table.insert(ocp1.fields, fieldDefs['ocaLibVolTypeAuthority'])
table.insert(ocp1.fields, fieldDefs['ocaLibVolTypeId'])

-- dissector for OcaLibVolType data type
function OcaLibVolType(buf, protofield, subtree)
    local authorityLength = OcaOrganizationID(buf(0):tvb(), nil, nil)

    if subtree ~= nil
    then
        local libVolType = subtree:add(protofield, buf(0, authorityLength + 1))
        OcaOrganizationID(buf(0):tvb(), fieldDefs['ocaLibVolTypeAuthority'], libVolType);
        managerDescriptor:add(fieldDefs['ocaLibVolTypeId'], buf(authorityLength, 1))
    end

    return (authorityLength + 1)
end

-----------------------------------------------------------------------
-- OcaList
-----------------------------------------------------------------------

-- message fields for OcaList data type
fieldDefs['ocaListCount'] = ProtoField.uint16("ocp.1.list.count", "Count", base.DEC)
table.insert(ocp1.fields, fieldDefs['ocaListCount'])

-- dissector for OcaList data type
function OcaList(buf, elementprotofield, elementdissector, subtree)
    local count = buf(0, 2):uint()
    local length = 2
    local list = nil

    if subtree ~= nil
    then
        list = subtree:add("OcaList")
        list:add(fieldDefs['ocaListCount'], buf(0, 2))
    end

    for elem = 1, count, 1
    do
        length = length + elementdissector(buf(length):tvb(), elementprotofield, list)
    end

    return length
end

-----------------------------------------------------------------------
-- OcaManagerDescriptor
-----------------------------------------------------------------------

-- message fields for OcaManagerDescriptor data type
fieldDefs['ocaManagerDescriptorObjectNumber'] = ProtoField.uint32("ocp.1.mandesc.ono", "Object Number", base.DEC)
fieldDefs['ocaManagerDescriptorName'] = ProtoField.string("ocp.1.mandesc.name", "Name", base.UNICODE)
fieldDefs['ocaManagerDescriptorClassID'] = ProtoField.bytes("ocp.1.mandesc.classid", "Class ID")
fieldDefs['ocaManagerDescriptorClassVersion'] = ProtoField.uint16("ocp.1.mandesc.classvers", "Class Version", base.DEC)
table.insert(ocp1.fields, fieldDefs['ocaManagerDescriptorObjectNumber'])
table.insert(ocp1.fields, fieldDefs['ocaManagerDescriptorName'])
table.insert(ocp1.fields, fieldDefs['ocaManagerDescriptorClassID'])
table.insert(ocp1.fields, fieldDefs['ocaManagerDescriptorClassVersion'])

-- dissector for OcaManagerDescriptor data type
function OcaManagerDescriptor(buf, protofield, subtree)
    local nameLength = OcaString(buf(4):tvb(), nil, nil)
    local classIDLength = OcaClassID(buf(4 + nameLength):tvb(), nil, nil)

    if subtree ~= nil
    then
        local managerDescriptor = subtree:add(protofield, buf(0, 4 + nameLength + classIDLength + 2))
        OcaONo(buf(0):tvb(), fieldDefs['ocaManagerDescriptorObjectNumber'], managerDescriptor);
        OcaString(buf(4):tvb(), fieldDefs['ocaManagerDescriptorName'], managerDescriptor)
        OcaClassID(buf(4 + nameLength):tvb(), fieldDefs['ocaManagerDescriptorClassID'], managerDescriptor)
        managerDescriptor:add(fieldDefs['ocaManagerDescriptorClassVersion'], buf(4 + nameLength + classIDLength, 2))
    end

    return (4 + nameLength + classIDLength + 2)
end

-----------------------------------------------------------------------
-- OcaMap
-----------------------------------------------------------------------

-- message fields for OcaMap data type
fieldDefs['ocaMapCount'] = ProtoField.uint16("ocp.1.map.count", "Count", base.DEC)
table.insert(ocp1.fields, fieldDefs['ocaMapCount'])

-- dissector for OcaMap data type
function OcaMap(buf, keyprotofield, keydissector, valueprotofield, valuedissector, subtree)
    local count = buf(0, 2):uint()
    local length = 2
    local map = nil

    if subtree ~= nil
    then
        map = subtree:add("OcaMap")
        map:add(fieldDefs['ocaMapCount'], buf(0, 2))
    end

    for elem = 1, count, 1
    do
        local key = map:add("Key")
        length = length + keydissector(buf(length):tvb(), keyprotofield, key)
        local value = map:add("Value")
        length = length + valuedissector(buf(length):tvb(), valueprotofield, value)
    end

    return length
end

-----------------------------------------------------------------------
-- OcaMediaCodingSchemeID
-----------------------------------------------------------------------

-- dissector for OcaMediaCodingSchemeID data type
function OcaMediaCodingSchemeID(buf, protofield, subtree)
    return OcaUint16(buf, protofield, subtree)
end

-----------------------------------------------------------------------
-- OcaMessageParameters (pseudo type)
-----------------------------------------------------------------------

-- message fields for OcaMessageParameters data type
fieldDefs['ocaMessageParametersCount'] = ProtoField.uint8("ocp.1.mesgparm.count", "Parameter Count", base.DEC)
fieldDefs['ocaMessageParametersData'] = ProtoField.bytes("ocp.1.mesgparm.data", "Data")
table.insert(ocp1.fields, fieldDefs['ocaMessageParametersCount'])
table.insert(ocp1.fields, fieldDefs['ocaMessageParametersData'])

-- dissector for OcaMessageParameters data type
function OcaMessageParameters(buf, protofield, size, subtree)
    if subtree ~= nil
    then
        local messageParameters = subtree:add(protofield, buf(0, size))
        messageParameters:add(fieldDefs['ocaMessageParametersCount'], buf(0, 1))
        if size > 1
        then
            messageParameters:add(fieldDefs['ocaMessageParametersData'], buf(1, size - 1))
        end
    end

    return size
end

-----------------------------------------------------------------------
-- OcaMethod
-----------------------------------------------------------------------

-- message fields for OcaMethod data type
fieldDefs['ocaMethodONo'] = ProtoField.uint32("ocp.1.method.ono", "Object Number", base.DEC)
fieldDefs['ocaMethodMethodID'] = ProtoField.bytes("ocp.1.method.methodid", "Method ID")
table.insert(ocp1.fields, fieldDefs['ocaMethodONo'])
table.insert(ocp1.fields, fieldDefs['ocaMethodMethodID'])

-- dissector for OcaMethod data type
function OcaMethod(buf, protofield, subtree)
    local methodIDLength = OcaMethodID(buf(4):tvb(), nil, nil)

    if subtree ~= nil
    then
        local method = subtree:add(protofield, buf(0, methodIDLength + 4))
        OcaONo(buf(0):tvb(), fieldDefs['ocaMethodONo'], method);
        OcaMethodID(buf(4):tvb(), fieldDefs['ocaMethodMethodID'], method);
    end

    return (4 + methodIDLength)
end

-----------------------------------------------------------------------
-- OcaMethodID
-----------------------------------------------------------------------

-- message fields for OcaMethodID data type
fieldDefs['ocaMethodIDDefLevel'] = ProtoField.uint16("ocp.1.methodid.level", "Definition Level", base.DEC)
fieldDefs['ocaMethodIDIndex'] = ProtoField.uint16("ocp.1.methodid.index", "Method Index", base.DEC)
table.insert(ocp1.fields, fieldDefs['ocaMethodIDDefLevel'])
table.insert(ocp1.fields, fieldDefs['ocaMethodIDIndex'])

-- dissector for OcaMethodID data type
function OcaMethodID(buf, protofield, subtree)
    if subtree ~= nil
    then
        local methodID = subtree:add(protofield, buf(0, 4))
        methodID:add(fieldDefs['ocaMethodIDDefLevel'], buf(0, 2))
        methodID:add(fieldDefs['ocaMethodIDIndex'], buf(2, 2))
    end

    return 4
end

-----------------------------------------------------------------------
-- OcaModelDescription
-----------------------------------------------------------------------

-- message fields for OcaModelDescription data type
fieldDefs['ocaModelDescriptionManufacturer'] = ProtoField.string("ocp.1.modeldesc.manf", "Manufacturer", base.UNICODE)
fieldDefs['ocaModelDescriptionName'] = ProtoField.string("ocp.1.modeldesc.name", "Name", base.UNICODE)
fieldDefs['ocaModelDescriptionVersion'] = ProtoField.string("ocp.1.modeldesc.version", "Version", base.UNICODE)
table.insert(ocp1.fields, fieldDefs['ocaModelDescriptionManufacturer'])
table.insert(ocp1.fields, fieldDefs['ocaModelDescriptionName'])
table.insert(ocp1.fields, fieldDefs['ocaModelDescriptionVersion'])

-- dissector for OcaModelDescription data type
function OcaModelDescription(buf, protofield, subtree)
    local manufacturerLength = OcaString(buf(0):tvb(), nil, nil)
    local nameLength = OcaString(buf(manufacturerLength):tvb(), nil, nil)
    local versionLength = OcaString(buf(manufacturerLength + nameLength):tvb(), nil, nil)

    if subtree ~= nil
    then
        local modelDescription = subtree:add(protofield, buf(0, manufacturerLength + nameLength + versionLength))
        OcaString(buf(0):tvb(), fieldDefs['ocaModelDescriptionManufacturer'], modelDescription)
        OcaString(buf(manufacturerLength):tvb(), fieldDefs['ocaModelDescriptionName'], modelDescription)
        OcaString(buf(manufacturerLength + nameLength):tvb(), fieldDefs['ocaModelDescriptionVersion'], modelDescription)
    end

    return (manufacturerLength + nameLength + versionLength)
end

-----------------------------------------------------------------------
-- OcaModelGUID
-----------------------------------------------------------------------

-- message fields for OcaModelGUID data type
fieldDefs['ocaModelGUIDReserved'] = ProtoField.bytes("ocp.1.modelguid.reserverd", "Reserved")
fieldDefs['ocaModelGUIDMfrCode'] = ProtoField.bytes("ocp.1.modelguid.mfrcode", "Manufacturer Code")
fieldDefs['ocaModelGUIDModelCode'] = ProtoField.bytes("ocp.1.modelguid.modelcode", "Model Code")
table.insert(ocp1.fields, fieldDefs['ocaModelGUIDReserved'])
table.insert(ocp1.fields, fieldDefs['ocaModelGUIDMfrCode'])
table.insert(ocp1.fields, fieldDefs['ocaModelGUIDModelCode'])

-- dissector for OcaModelGUID data type
function OcaModelGUID(buf, protofield, subtree)
    local reservedKeyLength = OcaBlobFixedLen(1, buf(0):tvb(), nil, nil)
    local mfrCodeLength = OcaBlobFixedLen(3, buf(reservedKeyLength):tvb(), nil, nil)
    local modelCodeLength = OcaBlobFixedLen(4, buf(reservedKeyLength + mfrCodeLength):tvb(), nil, nil)

    if subtree ~= nil
    then
        local modelGUID = subtree:add(protofield, buf(0, reservedKeyLength + mfrCodeLength + modelCodeLength))
        OcaBlobFixedLen(1, buf(0):tvb(), fieldDefs['ocaModelGUIDReserved'], modelGUID)
        OcaBlobFixedLen(3, buf(reservedKeyLength):tvb(), fieldDefs['ocaModelGUIDMfrCode'], modelGUID)
        OcaBlobFixedLen(4, buf(reservedKeyLength + mfrCodeLength):tvb(), fieldDefs['ocaModelGUIDModelCode'], modelGUID)
    end

    return (reservedKeyLength + mfrCodeLength + modelCodeLength)
end

-----------------------------------------------------------------------
-- OcaNamePath
-----------------------------------------------------------------------

-- message fields for OcaNamePath data type
fieldDefs['ocaNamePathName'] = ProtoField.string("ocp.1.namepath.name", "Name", base.UNICODE)
table.insert(ocp1.fields, fieldDefs['ocaNamePathName'])

-- dissector for OcaNamePath data type
function OcaNamePath(buf, protofield, subtree)
    local pathLength = OcaList(buf, fieldDefs['ocaNamePathName'], OcaString, nil)

    if subtree ~= nil
    then
        local namePath = subtree:add(protofield, buf(0, pathLength))
        OcaList(buf, fieldDefs['ocaNamePathName'], OcaString, namePath)
    end

    return pathLength
end

-----------------------------------------------------------------------
-- OcaNetworkAddress
-----------------------------------------------------------------------

-- dissector for OcaNetworkAddress data type
function OcaNetworkAddress(buf, protofield, subtree)
    return OcaBlob(buf, protofield, subtree)
end

-----------------------------------------------------------------------
-- OcaObjectIdentification
-----------------------------------------------------------------------

-- message fields for OcaObjectIdentification data type
fieldDefs['ocaObjectIdentificationONo'] = ProtoField.uint32("ocp.1.objidf.ono", "Object Number")
fieldDefs['ocaObjectIdentificationClassIdentification'] = ProtoField.bytes("ocp.1.objidf.classidf", "Class Identification")
table.insert(ocp1.fields, fieldDefs['ocaObjectIdentificationONo'])
table.insert(ocp1.fields, fieldDefs['ocaObjectIdentificationClassIdentification'])

-- dissector for OcaObjectIdentification data type
function OcaObjectIdentification(buf, protofield, subtree)
    local classIdentificationLength = OcaClassIdentification(buf(4):tvb(), nil, nil)

    if subtree ~= nil
    then
        local objectIdentification = subtree:add(protofield, buf(0, 4 + classIdentificationLength))
        OcaONo(buf(0):tvb(), fieldDefs['ocaObjectIdentificationONo'], objectIdentification)
        OcaClassIdentification(buf(4):tvb(), fieldDefs['ocaObjectIdentificationClassIdentification'], objectIdentification)
    end

    return (4 + classIdentificationLength)
end

-----------------------------------------------------------------------
-- OcaObjectSearchResult
-----------------------------------------------------------------------

-- message fields for OcaObjectSearchResult data type
fieldDefs['ocaObjectSearchResultONo'] = ProtoField.uint32("ocp.1.objsrchres.ono", "Object Number")
fieldDefs['ocaObjectSearchResultClassIdentification'] = ProtoField.bytes("ocp.1.objsrchres.classidf", "Class Identification")
fieldDefs['ocaObjectSearchResultContainerPath'] = ProtoField.bytes("ocp.1.objsrchres.cntpath", "Container Path")
fieldDefs['ocaObjectSearchResultRole'] = ProtoField.string("ocp.1.objsrchres.role", "Role", base.UNICODE)
fieldDefs['ocaObjectSearchResultLabel'] = ProtoField.string("ocp.1.objsrchres.label", "Label", base.UNICODE)
table.insert(ocp1.fields, fieldDefs['ocaObjectSearchResultONo'])
table.insert(ocp1.fields, fieldDefs['ocaObjectSearchResultClassIdentification'])
table.insert(ocp1.fields, fieldDefs['ocaObjectSearchResultContainerPath'])
table.insert(ocp1.fields, fieldDefs['ocaObjectSearchResultRole'])
table.insert(ocp1.fields, fieldDefs['ocaObjectSearchResultLabel'])

-- dissector for OcaObjectSearchResult data type
function OcaObjectSearchResult(buf, protofield, subtree)
    local classIdentificationLength = OcaClassIdentification(buf(4):tvb(), nil, nil)
    local containerPathLength = OcaONoPath(buf(4 + classIdentificationLength):tvb(), nil, nil)
    local roleLength = OcaString(buf(4 + classIdentificationLength + containerPathLength):tvb(), nil, nil)
    local labelLength = OcaString(buf(4 + classIdentificationLength + containerPathLength + roleLength):tvb(), nil, nil)

    if subtree ~= nil
    then
        local objectSearchResult = subtree:add(protofield, buf(0, 4 + classIdentificationLength + containerPathLength + roleLength + labelLength))
        OcaONo(buf(0):tvb(), fieldDefs['ocaObjectSearchResultONo'], objectSearchResult)
        OcaClassIdentification(buf(4):tvb(), fieldDefs['ocaObjectSearchResultClassIdentification'], objectSearchResult)
        OcaONoPath(buf(4 + classIdentificationLength):tvb(), fieldDefs['ocaObjectSearchResultContainerPath'], objectSearchResult)
        OcaString(buf(4 + classIdentificationLength + containerPathLength):tvb(), fieldDefs['ocaObjectSearchResultRole'], objectSearchResult)
        OcaString(buf(4 + classIdentificationLength + containerPathLength + roleLength):tvb(), fieldDefs['ocaObjectSearchResultLabel'], objectSearchResult)
    end

    return (4 + classIdentificationLength + containerPathLength + roleLength + labelLength)
end

-----------------------------------------------------------------------
-- OcaONo
-----------------------------------------------------------------------

-- dissector for OcaONo data type
function OcaONo(buf, protofield, subtree)
    return OcaUint32(buf, protofield, subtree)
end

-----------------------------------------------------------------------
-- OcaONoPath
-----------------------------------------------------------------------

-- message fields for OcaONoPath data type
fieldDefs['ocaONoPathONo'] = ProtoField.uint32("ocp.1.onopath.ono", "Object Number")
table.insert(ocp1.fields, fieldDefs['ocaONoPathONo'])

-- dissector for OcaONoPath data type
function OcaONoPath(buf, protofield, subtree)
    local pathLength = OcaList(buf, fieldDefs['ocaONoPathONo'], OcaONo, nil)

    if subtree ~= nil
    then
        local oNoPath = subtree:add(protofield, buf(0, pathLength))
        OcaList(buf, fieldDefs['ocaONoPathONo'], OcaONo, oNoPath)
    end

    return pathLength
end

-----------------------------------------------------------------------
-- OcaOrganizationID
-----------------------------------------------------------------------

-- dissector for OcaOrganizationID data type
function OcaOrganizationID(buf, protofield, subtree)
    return OcaBlobFixedLen(3, buf, protofield, subtree)
end

-----------------------------------------------------------------------
-- OcaPort
-----------------------------------------------------------------------

-- message fields for OcaPort data type
fieldDefs['ocaPortOwner'] = ProtoField.uint32("ocp.1.port.owner", "Owner", base.DEC)
fieldDefs['ocaPortID'] = ProtoField.bytes("ocp.1.port.id", "ID")
fieldDefs['ocaPortName'] = ProtoField.string("ocp.1.port.name", "Name", base.UNICODE)
table.insert(ocp1.fields, fieldDefs['ocaPortOwner'])
table.insert(ocp1.fields, fieldDefs['ocaPortID'])
table.insert(ocp1.fields, fieldDefs['ocaPortName'])

-- dissector for OcaPort data type
function OcaPort(buf, protofield, subtree)
    local idLength = OcaPortID(buf(4):tvb(), nil, nil)
    local nameLength = OcaString(buf(4 + idLength):tvb(), nil, nil)

    if subtree ~= nil
    then
        local port = subtree:add(protofield, buf(0, 4 + idLength + nameLength))
        OcaONo(buf(0):tvb(), fieldDefs['ocaPortOwner'], port)
        OcaPortID(buf(4):tvb(), fieldDefs['ocaPortID'], port)
        OcaString(buf(4 + idLength):tvb(), fieldDefs['ocaPortName'], port)
    end

    return (4 + idLength + nameLength)
end

-----------------------------------------------------------------------
-- OcaPortID
-----------------------------------------------------------------------

-- message fields for OcaPortID data type
fieldDefs['ocaPortIDMode'] = ProtoField.uint8("ocp.1.portid.mode", "Mode", base.DEC, ocaPortModeToString)
fieldDefs['ocaPortIDIdx'] = ProtoField.uint16("ocp.1.portid.index", "Index", base.DEC)
table.insert(ocp1.fields, fieldDefs['ocaPortIDMode'])
table.insert(ocp1.fields, fieldDefs['ocaPortIDIdx'])

-- dissector for OcaPortID data type
function OcaPortID(buf, protofield, subtree)
    if subtree ~= nil
    then
        local portID = subtree:add(protofield, buf(0, 3))
        portID:add(fieldDefs['ocaPortIDMode'], buf(0, 1))
        portID:add(fieldDefs['ocaPortIDIdx'], buf(1, 2))
    end

    return 3
end

-----------------------------------------------------------------------
-- OcaProtoONo
-----------------------------------------------------------------------

-- dissector for OcaProtoONo data type
function OcaProtoONo(buf, protofield, subtree)
    OcaUint32(buf, protofield, subtree)
end

-----------------------------------------------------------------------
-- OcaSignalPath
-----------------------------------------------------------------------

-- message fields for OcaSignalPath data type
fieldDefs['ocaSignalPathSourcePort'] = ProtoField.bytes("ocp.1.sigpath.source", "Source Port")
fieldDefs['ocaSignalPathSinkPort'] = ProtoField.bytes("ocp.1.sigpath.sink", "Sink Port")
table.insert(ocp1.fields, fieldDefs['ocaSignalPathSourcePort'])
table.insert(ocp1.fields, fieldDefs['ocaSignalPathSinkPort'])

-- dissector for OcaSignalPath data type
function OcaSignalPath(buf, protofield, subtree)
    local sourcePortLength = OcaPort(buf(0):tvb(), nil, nil)
    local sinkPortLength = OcaPort(buf(sourcePortLength):tvb(), nil, nil)

    if subtree ~= nil
    then
        local signalPath = subtree:add(protofield, buf(0, sourcePortLength + sinkPortLength))
        OcaPort(buf(0):tvb(), fieldDefs['ocaSignalPathSourcePort'], signalPath)
        OcaPort(buf(sourcePortLength):tvb(), fieldDefs['ocaSignalPathSinkPort'], signalPath)
    end

    return (sourcePortLength + sinkPortLength)
end

-----------------------------------------------------------------------
-- OcaString
-----------------------------------------------------------------------

-- message fields for OcaString data type
fieldDefs['ocaStringLength'] = ProtoField.uint16("ocp.1.string.length", "Length", base.DEC)
fieldDefs['ocaStringData'] = ProtoField.bytes("ocp.1.string.data", "Data")
table.insert(ocp1.fields, fieldDefs['ocaStringLength'])
table.insert(ocp1.fields, fieldDefs['ocaStringData'])

-- dissector for OcaString data type
function OcaString(buf, protofield, subtree)
    local stringLength = buf(0, 2):uint()
    local byteLength = 2
    local readChars = 0

    while readChars < stringLength
    do
        local char = buf(byteLength, 1):uint()
        if char < 0x80
        then
            byteLength = byteLength + 1
        elseif bit.band(char, 0xE0) == 0xC0
        then
            byteLength = byteLength + 2
        elseif bit.band(char, 0xF0) == 0xE0
        then
            byteLength = byteLength + 3
        elseif bit.band(char, 0xF8) == 0xF0
        then
            byteLength = byteLength + 4
        end

        readChars = readChars + 1
    end

    if subtree ~= nil
    then
--        local stringTree = subtree:add(protofield, buf(2, byteLength - 2))
        local stringTree = subtree:add_packet_field(protofield, buf(2, byteLength - 2), ENC_UTF_8)
        stringTree:add(fieldDefs['ocaStringLength'], buf(0, 2))
        stringTree:add(fieldDefs['ocaStringData'], buf(2, byteLength - 2))
    end

    return byteLength
end

-----------------------------------------------------------------------
-- OcaTimeNTP
-----------------------------------------------------------------------

-- message fields for OcaTimeNTP data type
fieldDefs['ocaTimeNTPSeconds'] = ProtoField.uint32("ocp.1.ntp.seconds", "Seconds Since 1/1/1900", base.DEC)
fieldDefs['ocaTimeNTPFraction'] = ProtoField.uint32("ocp.1.ntp.fraction", "Fraction")
table.insert(ocp1.fields, fieldDefs['ocaTimeNTPSeconds'])
table.insert(ocp1.fields, fieldDefs['ocaTimeNTPFraction'])

-- constants for date/time conversion of OcaTimeNTP
local SECS_PER_MINUTE = 60
local SECS_PER_HOUR = 60 * SECS_PER_MINUTE
local SECS_PER_DAY = 24 * SECS_PER_HOUR
local EPOCH_YEAR = 1900
local DAYS_PER_NON_LEAP_YEAR = 365
local DAYS_PER_LEAP_YEAR = 366
local FRACTION_DIVISOR = 2^32

-- helper function to determine the number of leap days through the end of the given year
local function GetLeapsThroughEndOf(year)
    return math.floor(year / 4) - math.floor(year / 100) + math.floor(year / 400)
end

-- helper function to determine whether a year is a leap year
local function IsLeapYear(year)
    return ((0 == math.floor(year / 400)) or
            ((0 == math.floor(year / 4)) and
             (0 ~= math.floor(year / 100))))
end

-- helper function to get the number of days in the given year
local function GetDaysInYear(year)
    local days = DAYS_PER_NON_LEAP_YEAR
    if (IsLeapYear(year))
    then
        days = DAYS_PER_LEAP_YEAR
    end

    return days
end

-- helper function to determine the number of days in the given month for the given year
local function GetDaysInMonth(year, month)
    local days = 31;

    if month == 2
    then
        if IsLeapYear(year)
        then
            days = 29
        else
            days = 28
        end
    elseif ((month == 4) or
            (month == 6) or
            (month == 9) or
            (month == 11))
    then
        days = 30
    end

    return days
end

-- helper function to add zeros to the start of the string to get a string of length count
local function PadZero(s, count)
    return (string.rep("0", count - string.len(s)) .. s)
end

-- dissector for OcaTimeNTP data type
function OcaTimeNTP(buf, protofield, subtree)
    if subtree ~= nil
    then
        -- Calculate the date parts (freely taken from the source code of localtime.c)
        local totalSeconds = buf(0, 4):uint()
        local days = math.floor(totalSeconds / SECS_PER_DAY)
        local remainder = totalSeconds % SECS_PER_DAY
        local hours = math.floor(remainder / SECS_PER_HOUR)
        remainder = remainder % SECS_PER_HOUR
        local minutes = math.floor(remainder / SECS_PER_MINUTE)
        local seconds = remainder % SECS_PER_MINUTE
        local year = EPOCH_YEAR
        while ((days < 0) or
               (days >= GetDaysInYear(year))) do
            local newYear = year + math.floor(days / DAYS_PER_NON_LEAP_YEAR)
            if (days < 0)
            then
                newYear = newYear - 1;
            end
            days = days - (((newYear - year) * DAYS_PER_NON_LEAP_YEAR) + GetLeapsThroughEndOf(newYear - 1) - GetLeapsThroughEndOf(year - 1))
            year = newYear
        end
        local month = 1
        while days >= GetDaysInMonth(year, month) do
            days = days - GetDaysInMonth(year, month)
            month = month + 1
        end
        local monthDay = days + 1
        local fractionMilliseconds = math.floor(((buf(4, 4):uint() / FRACTION_DIVISOR) * 1000) + 0.5)

        -- Create the formatted date
        local timeString = PadZero(year, 4) .. '-' .. PadZero(month, 2) .. '-' .. PadZero(monthDay, 2) .. 'T' .. PadZero(hours, 2) .. ':' .. PadZero(minutes, 2) .. ':' .. PadZero(seconds, 2) .. '.' .. PadZero(fractionMilliseconds, 3) .. 'Z'

        -- Add the tree
        local timeOfDayTree = subtree:add(protofield, buf(0, 8))
        timeOfDayTree:add(fieldDefs['ocaTimeNTPSeconds'], buf(0, 4))
        timeOfDayTree:add(fieldDefs['ocaTimeNTPFraction'], buf(4, 4))
        timeOfDayTree:add(protofield, buf(0, 8)):set_text('Time stamp: ' .. timeString)

    end

    return 8
end

-----------------------------------------------------------------------
-- OcaTimePTP
-----------------------------------------------------------------------

-- message fields for OcaTimePTP data type
fieldDefs['ocaTimePTPNegative'] = ProtoField.uint8("ocp.1.ptp.neg", "Negative", base.DEC, boolToYesNoString)
fieldDefs['ocaTimePTPSeconds'] = ProtoField.uint64("ocp.1.ptp.sec", "Seconds", base.DEC)
fieldDefs['ocaTimePTPNanoSeconds'] = ProtoField.uint32("ocp.1.ptp.nanosec", "Nano Seconds", base.DEC)
table.insert(ocp1.fields, fieldDefs['ocaTimePTPNegative'])
table.insert(ocp1.fields, fieldDefs['ocaTimePTPSeconds'])
table.insert(ocp1.fields, fieldDefs['ocaTimePTPNanoSeconds'])

-- dissector for OcaTimePTP data type
function OcaTimePTP(buf, protofield, subtree)
    if subtree ~= nil
    then
        local timePTP = subtree:add(protofield, buf(0, 1 + 8 + 4))
        timePTP:add(fieldDefs['ocaTimePTPNegative'], buf(0, 1))
        OcaUint64(buf(1, 8):tvb(), fieldDefs['ocaTimePTPSeconds'], timePTP);
        OcaUint32(buf(9, 4):tvb(), fieldDefs['ocaTimePTPNanoSeconds'], timePTP);
    end

    return (1 + 8 + 4)
end

-----------------------------------------------------------------------
-- OcaUint16
-----------------------------------------------------------------------

-- dissector for OcaUint16 data type
function OcaUint16(buf, protofield, subtree)
    if subtree ~= nil
    then
        subtree:add(protofield, buf(0, 2))
    end

    return 2
end

-----------------------------------------------------------------------
-- OcaUint32
-----------------------------------------------------------------------

-- dissector for OcaUint32 data type
function OcaUint32(buf, protofield, subtree)
    if subtree ~= nil
    then
        subtree:add(protofield, buf(0, 4))
    end

    return 4
end

-----------------------------------------------------------------------
-- OcaUint64
-----------------------------------------------------------------------

-- dissector for OcaUint64 data type
function OcaUint64(buf, protofield, subtree)
    if subtree ~= nil
    then
        subtree:add(protofield, buf(0, 8))
    end

    return 8
end

-----------------------------------------------------------------------
-- OcaVersion
-----------------------------------------------------------------------

-- message fields for OcaVersion data type
fieldDefs['ocaVersionMajor'] = ProtoField.uint32("ocp.1.version.major", "Major", base.DEC)
fieldDefs['ocaVersionMinor'] = ProtoField.uint32("ocp.1.version.minor", "Minor", base.DEC)
fieldDefs['ocaVersionBuild'] = ProtoField.uint32("ocp.1.version.build", "Build", base.DEC)
fieldDefs['ocaVersionComponent'] = ProtoField.uint16("ocp.1.version.comp", "Component", base.DEC, ocaComponentToString)
table.insert(ocp1.fields, fieldDefs['ocaVersionMajor'])
table.insert(ocp1.fields, fieldDefs['ocaVersionMinor'])
table.insert(ocp1.fields, fieldDefs['ocaVersionBuild'])
table.insert(ocp1.fields, fieldDefs['ocaVersionComponent'])

-- dissector for OcaVersion data type
function OcaVersion(buf, protofield, subtree)
    if subtree ~= nil
    then
        local version = subtree:add(protofield, buf(0, 3 * 4 + 2))
        version:add(fieldDefs['ocaVersionMajor'], buf(0, 4))
        version:add(fieldDefs['ocaVersionMinor'], buf(4, 4))
        version:add(fieldDefs['ocaVersionBuild'], buf(8, 4))
        version:add(fieldDefs['ocaVersionComponent'], buf(12, 2))
    end

    return (3 * 4 + 2)
end


-----------------------------------------------------------------------
-- DISSECTORS FOR OCA ROOT
-----------------------------------------------------------------------

-----------------------------------------------------------------------
-- OcaRoot
-----------------------------------------------------------------------

-- message fields for OcaRoot methods
fieldDefs['ocaRootClassIdentification'] = ProtoField.bytes("ocp.1.root.classidf", "Class Identification");
fieldDefs['ocaRootLockable'] = ProtoField.uint8("ocp.1.root.lockable", "Lockable", base.DEC, boolToYesNoString)
fieldDefs['ocaRootRole'] = ProtoField.string("ocp.1.devman.sernumber", "Role", base.UNICODE)
table.insert(ocp1.fields, fieldDefs['ocaRootClassIdentification'])
table.insert(ocp1.fields, fieldDefs['ocaRootLockable'])
table.insert(ocp1.fields, fieldDefs['ocaRootRole'])

-- dissector for OcaRoot GetClassIdentification response
function OcaRootGetClassIdentification(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaRoot.GetClassIdentification")
    OcaClassIdentification(parameters, fieldDefs['ocaRootClassIdentification'], classtree)
end

-- dissector for OcaRoot GetLockable response
function OcaRootGetLockable(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaRoot.GetLockable")
    classtree:add(fieldDefs['ocaRootLockable'], parameters(0, 1))
end

-- dissector for OcaRoot Lock response
function OcaRootLock(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaRoot.Lock")
end

-- dissector for OcaRoot Unlock response
function OcaRootUnlock(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaRoot.Unlock")
end

-- dissector for OcaRoot GetRole response
function OcaRootGetRole(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaRoot.GetRole")
    OcaString(parameters, fieldDefs['ocaRootRole'], classtree)
end

-- dissector for OcaRoot LockReadonly response
function OcaRootLockReadonly(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaRoot.LockReadonly")
end

-- dissector for OcaRoot object
function OcaRoot(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 1
    then
        subtree:add("Incorrect definition level")
    elseif defLevel == 1
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaRoot.GetClassIdentification")
            -- no parameters to be decoded
            responseDissector = OcaRootGetClassIdentification
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaRoot.GetLockable")
            -- no parameters to be decoded
            responseDissector = OcaRootGetLockable
        elseif methodIndex == 3
        then
            local classtree = subtree:add("OcaRoot.Lock")
            -- no parameters to be decoded
            responseDissector = OcaRootLock
        elseif methodIndex == 4
        then
            local classtree = subtree:add("OcaRoot.Unlock")
            -- no parameters to be decoded
            responseDissector = OcaRootUnlock
        elseif methodIndex == 5
        then
            local classtree = subtree:add("OcaRoot.GetRole")
            -- no parameters to be decoded
            responseDissector = OcaRootGetRole
        elseif methodIndex == 6
        then
            local classtree = subtree:add("OcaRoot.LockReadonly")
            -- no parameters to be decoded
            responseDissector = OcaRootLockReadonly
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end


-----------------------------------------------------------------------
-- DISSECTORS FOR OCA MANAGERS
-----------------------------------------------------------------------

-----------------------------------------------------------------------
-- OcaManager
-----------------------------------------------------------------------

-- dissector for OcaManager object
function OcaManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 2
    then
        responseDissector = OcaRoot(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 2
    then
        subtree:add("Unknown method")
    end

    return responseDissector
end

-----------------------------------------------------------------------
-- OcaDeviceManager
-----------------------------------------------------------------------

-- message fields for OcaDeviceManager methods
fieldDefs['ocaDeviceManagerOcaVersion'] = ProtoField.uint16("ocp.1.devman.ocaversion", "OCA Version", base.DEC)
fieldDefs['ocaDeviceManagerModelGUID'] = ProtoField.bytes("ocp.1.devman.modelguid", "Model GUID")
fieldDefs['ocaDeviceManagerSerialNumber'] = ProtoField.string("ocp.1.devman.sernumber", "Serial Number", base.UNICODE)
fieldDefs['ocaDeviceManagerDeviceName'] = ProtoField.string("ocp.1.devman.devname", "Device Name", base.UNICODE)
fieldDefs['ocaDeviceManagerModelDescription'] = ProtoField.bytes("ocp.1.devman.modeldescr", "Model Description")
fieldDefs['ocaDeviceManagerDeviceRole'] = ProtoField.string("ocp.1.devman.devrole", "Device Role", base.UNICODE)
fieldDefs['ocaDeviceManagerUserInventoryCode'] = ProtoField.string("ocp.1.devman.uic", "User Inventory Code", base.UNICODE)
fieldDefs['ocaDeviceManagerEnabled'] = ProtoField.uint8("ocp.1.devman.enabled", "Enabled", base.DEC, boolToYesNoString)
fieldDefs['ocaDeviceManagerState'] = ProtoField.uint16("ocp.1.devman.state", "State", base.HEX, ocaDeviceManagerStateToString)
fieldDefs['ocaDeviceManagerResetKey'] = ProtoField.bytes("ocp.1.devman.resetkey", "Reset Key")
fieldDefs['ocaDeviceManagerNetworkAddress'] = ProtoField.bytes("ocp.1.devman.netwaddr", "Network Address")
fieldDefs['ocaDeviceManagerResetCause'] = ProtoField.uint8("ocp.1.devman.resetcause", "Reset Cause", base.DEC, ocaDeviceManagerResetCauseToString)
fieldDefs['ocaDeviceManagerMessage'] = ProtoField.string("ocp.1.devman.message", "Message", base.UNICODE)
fieldDefs['ocaDeviceManagerManager'] = ProtoField.bytes("ocp.1.devman.manager", "Manager")
fieldDefs['ocaDeviceManagerDeviceRevisionID'] = ProtoField.string("ocp.1.devman.devrevid", "Device Revision ID", base.UNICODE)
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerOcaVersion'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerModelGUID'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerSerialNumber'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerDeviceName'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerModelDescription'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerDeviceRole'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerUserInventoryCode'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerEnabled'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerState'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerResetKey'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerNetworkAddress'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerResetCause'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerMessage'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerManager'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceManagerDeviceRevisionID'])

-- dissector for OcaDeviceManager GetOcaVersion response
function OcaDeviceManagerGetOcaVersion(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.GetOcaVersion")
    classtree:add(fieldDefs['ocaDeviceManagerOcaVersion'], parameters(0, 2))
end

-- dissector for OcaDeviceManager GetModelGUID response
function OcaDeviceManagerGetModelGUID(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.GetModelGUID")
    OcaModelGUID(parameters(0):tvb(), fieldDefs['ocaDeviceManagerModelGUID'], classtree)
end

-- dissector for OcaDeviceManager GetSerialNumber response
function OcaDeviceManagerGetSerialNumber(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.GetSerialNumber")
    OcaString(parameters(0):tvb(), fieldDefs['ocaDeviceManagerSerialNumber'], classtree)
end

-- dissector for OcaDeviceManager GetDeviceName response
function OcaDeviceManagerGetDeviceName(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.GetDeviceName")
    OcaString(parameters(0):tvb(), fieldDefs['ocaDeviceManagerDeviceName'], classtree)
end

-- dissector for OcaDeviceManager SetDeviceName response
function OcaDeviceManagerSetDeviceName(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.SetDeviceName")
end

-- dissector for OcaDeviceManager GetModelDescription response
function OcaDeviceManagerGetModelDescription(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.GetModelDescription")
    OcaModelDescription(parameters(0):tvb(), fieldDefs['ocaDeviceManagerModelDescription'], classtree)
end

-- dissector for OcaDeviceManager GetDeviceRole response
function OcaDeviceManagerGetDeviceRole(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.GetDeviceRole")
    OcaString(parameters(0):tvb(), fieldDefs['ocaDeviceManagerDeviceRole'], classtree)
end

-- dissector for OcaDeviceManager SetDeviceRole response
function OcaDeviceManagerSetDeviceRole(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.SetDeviceRole")
end

-- dissector for OcaDeviceManager GetUserInventoryCode response
function OcaDeviceManagerGetUserInventoryCode(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.GetUserInventoryCode")
    OcaString(parameters(0):tvb(), fieldDefs['ocaDeviceManagerUserInventoryCode'], classtree)
end

-- dissector for OcaDeviceManager SetUserInventoryCode response
function OcaDeviceManagerSetUserInventoryCode(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.SetUserInventoryCode")
end

-- dissector for OcaDeviceManager GetEnabled response
function OcaDeviceManagerGetEnabled(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.GetEnabled")
    classtree:add(fieldDefs['ocaDeviceManagerEnabled'], parameters(0, 1))
end

-- dissector for OcaDeviceManager SetEnabled response
function OcaDeviceManagerSetEnabled(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.SetEnabled")
end

-- dissector for OcaDeviceManager GetState response
function OcaDeviceManagerGetState(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.GetState")
    classtree:add(fieldDefs['ocaDeviceManagerState'], parameters(0, 2))
end

-- dissector for OcaDeviceManager SetResetKey response
function OcaDeviceManagerSetResetKey(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.SetResetKey")
end

-- dissector for OcaDeviceManager GetResetCause response
function OcaDeviceManagerGetResetCause(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.GetResetCause")
    classtree:add(fieldDefs['ocaDeviceManagerResetCause'], parameters(0, 1))
end

-- dissector for OcaDeviceManager ClearResetCase response
function OcaDeviceManagerClearResetCase(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.ClearResetCase")
end

-- dissector for OcaDeviceManager GetMessage response
function OcaDeviceManagerGetMessage(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.GetMessage")
    OcaString(parameters(0):tvb(), fieldDefs['ocaDeviceManagerMessage'], classtree)
end

-- dissector for OcaDeviceManager SetMessage response
function OcaDeviceManagerSetMessage(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.SetMessage")
end

-- dissector for OcaDeviceManager GetManagers response
function OcaDeviceManagerGetManagers(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.GetManagers")
    OcaList(parameters, fieldDefs["ocaDeviceManagerManager"], OcaManagerDescriptor, classtree)
end

-- dissector for OcaDeviceManager GetDeviceRevisionID response
function OcaDeviceManagerGetDeviceRevisionID(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceManager.GetDeviceRevisionID")
    OcaString(parameters(0):tvb(), fieldDefs['ocaDeviceManagerDeviceRevisionID'], classtree)
end

-- dissector for OcaDeviceManager object
function OcaDeviceManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 3
    then
        responseDissector = OcaManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 3
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaDeviceManager.GetOcaVersion")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerGetOcaVersion
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaDeviceManager.GetModelGUID")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerGetModelGUID
        elseif methodIndex == 3
        then
            local classtree = subtree:add("OcaDeviceManager.GetSerialNumber")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerGetSerialNumber
        elseif methodIndex == 4
        then
            local classtree = subtree:add("OcaDeviceManager.GetDeviceName")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerGetDeviceName
        elseif methodIndex == 5
        then
            local classtree = subtree:add("OcaDeviceManager.SetDeviceName")
            OcaString(parameters(0):tvb(), fieldDefs['ocaDeviceManagerDeviceName'], classtree)
            responseDissector = OcaDeviceManagerSetDeviceName
        elseif methodIndex == 6
        then
            local classtree = subtree:add("OcaDeviceManager.GetModelDescription")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerGetModelDescription
        elseif methodIndex == 7
        then
            local classtree = subtree:add("OcaDeviceManager.GetDeviceRole")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerGetDeviceRole
        elseif methodIndex == 8
        then
            local classtree = subtree:add("OcaDeviceManager.SetDeviceRole")
            OcaString(parameters(0):tvb(), fieldDefs['ocaDeviceManagerDeviceRole'], classtree)
            responseDissector = OcaDeviceManagerSetDeviceRole
        elseif methodIndex == 9
        then
            local classtree = subtree:add("OcaDeviceManager.GetUserInventoryCode")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerGetUserInventoryCode
        elseif methodIndex == 10
        then
            local classtree = subtree:add("OcaDeviceManager.SetUserInventoryCode")
            OcaString(parameters(0):tvb(), fieldDefs['ocaDeviceManagerUserInventoryCode'], classtree)
            responseDissector = OcaDeviceManagerSetUserInventoryCode
        elseif methodIndex == 11
        then
            local classtree = subtree:add("OcaDeviceManager.GetEnabled")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerGetEnabled
        elseif methodIndex == 12
        then
            local classtree = subtree:add("OcaDeviceManager.SetEnabled")
            classtree:add(fieldDefs['ocaDeviceManagerEnabled'], parameters(0, 1))
            responseDissector = OcaDeviceManagerSetEnabled
        elseif methodIndex == 13
        then
            local classtree = subtree:add("OcaDeviceManager.GetState")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerGetState
        elseif methodIndex == 14
        then
            local classtree = subtree:add("OcaDeviceManager.SetResetKey")
            local resetKeyLength = OcaBlobFixedLen(16, parameters(0):tvb(), fieldDefs['ocaDeviceManagerResetKey'], classtree)
            OcaNetworkAddress(parameters(resetKeyLength):tvb(), fieldDefs['ocaDeviceManagerNetworkAddress'], classtree)
            responseDissector = OcaDeviceManagerSetResetKey
        elseif methodIndex == 15
        then
            local classtree = subtree:add("OcaDeviceManager.GetResetCause")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerGetResetCause
        elseif methodIndex == 16
        then
            local classtree = subtree:add("OcaDeviceManager.ClearResetCase")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerClearResetCase
        elseif methodIndex == 17
        then
            local classtree = subtree:add("OcaDeviceManager.GetMessage")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerGetMessage
        elseif methodIndex == 18
        then
            local classtree = subtree:add("OcaDeviceManager.SetMessage")
            OcaString(parameters(0):tvb(), fieldDefs['ocaDeviceManagerMessage'], classtree)
            responseDissector = OcaDeviceManagerSetMessage
        elseif methodIndex == 19
        then
            local classtree = subtree:add("OcaDeviceManager.GetManagers")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerGetManagers
        elseif methodIndex == 20
        then
            local classtree = subtree:add("OcaDeviceManager.GetDeviceRevisionID")
            -- no parameters to be decoded
            responseDissector = OcaDeviceManagerGetDeviceRevisionID
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end

fixedObjectDissector[1] = OcaDeviceManager

-----------------------------------------------------------------------
-- OcaSecurityManager
-----------------------------------------------------------------------

-- message fields for OcaSecurityManager methods
fieldDefs['ocaSecurityManagerKeyIdentity'] = ProtoField.string("ocp.1.secman.keyid", "Key Identity", base.UNICODE)
fieldDefs['ocaSecurityManagerKey'] = ProtoField.bytes("ocp.1.secman.key", "Key")
table.insert(ocp1.fields, fieldDefs['ocaSecurityManagerKeyIdentity'])
table.insert(ocp1.fields, fieldDefs['ocaSecurityManagerKey'])

-- dissector for OcaSecurityManager EnableControlSecurity response
function OcaSecurityManagerEnableControlSecurity(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaSecurityManager.EnableControlSecurity")
end

-- dissector for OcaSecurityManager DisableControlSecurity response
function OcaSecurityManagerDisableControlSecurity(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaSecurityManager.DisableControlSecurity")
end

-- dissector for OcaSecurityManager ChangePreSharedKey response
function OcaSecurityManagerChangePreSharedKey(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaSecurityManager.ChangePreSharedKey")
end

-- dissector for OcaSecurityManager AddPreSharedKey response
function OcaSecurityManagerAddPreSharedKey(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaSecurityManager.AddPreSharedKey")
end

-- dissector for OcaSecurityManager DeletePreSharedKey response
function OcaSecurityManagerDeletePreSharedKey(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaSecurityManager.DeletePreSharedKey")
end

-- dissector for OcaSecurityManager object
function OcaSecurityManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 3
    then
        responseDissector = OcaManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 3
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaSecurityManager.EnableControlSecurity")
            -- no parameters to be decoded
            responseDissector = OcaSecurityManagerEnableControlSecurity
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaSecurityManager.DisableControlSecurity")
            -- no parameters to be decoded
            responseDissector = OcaSecurityManagerDisableControlSecurity
        elseif methodIndex == 3
        then
            local classtree = subtree:add("OcaSecurityManager.ChangePreSharedKey")
            local keyIdentityLength = OcaString(parameters(0):tvb(), fieldDefs['ocaSecurityManagerKeyIdentity'], classtree)
            OcaBlob(parameters(keyIdentityLength):tvb(), fieldDefs['ocaSecurityManagerKey'], classtree)
            responseDissector = OcaSecurityManagerChangePreSharedKey
        elseif methodIndex == 4
        then
            local classtree = subtree:add("OcaSecurityManager.AddPreSharedKey")
            local keyIdentityLength = OcaString(parameters(0):tvb(), fieldDefs['ocaSecurityManagerKeyIdentity'], classtree)
            OcaBlob(parameters(keyIdentityLength):tvb(), fieldDefs['ocaSecurityManagerKey'], classtree)
            responseDissector = OcaSecurityManagerAddPreSharedKey
        elseif methodIndex == 5
        then
            local classtree = subtree:add("OcaSecurityManager.DeletePreSharedKey")
            OcaString(parameters(0):tvb(), fieldDefs['ocaSecurityManagerKeyIdentity'], classtree)
            responseDissector = OcaSecurityManagerAddPreSharedKey
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end

fixedObjectDissector[2] = OcaSecurityManager

-----------------------------------------------------------------------
-- OcaFirmwareManager
-----------------------------------------------------------------------

-- message fields for OcaFirmwareManager methods
fieldDefs['ocaFirmwareManagerComponentVersion'] = ProtoField.bytes("ocp.1.fwman.compver", "Component Version")
fieldDefs['ocaFirmwareManagerComponent'] = ProtoField.uint16("ocp.1.fwman.comp", "Component", base.DEC, ocaComponentToString)
fieldDefs['ocaFirmwareManagerImageId'] = ProtoField.uint32("ocp.1.fwman.imid", "Image ID", base.DEC)
fieldDefs['ocaFirmwareManagerImageData'] = ProtoField.bytes("ocp.1.fwman.imdata", "Image Data")
fieldDefs['ocaFirmwareManagerVerifyData'] = ProtoField.bytes("ocp.1.fwman.verdata", "Verify Data")
fieldDefs['ocaFirmwareManagerServerAddress'] = ProtoField.bytes("ocp.1.fwman.servaddr", "Server Address")
fieldDefs['ocaFirmwareManagerUpdateFileName'] = ProtoField.string("ocp.1.fwman.updfile", "Update File Name", base.UNICODE)
table.insert(ocp1.fields, fieldDefs['ocaFirmwareManagerComponentVersion'])
table.insert(ocp1.fields, fieldDefs['ocaFirmwareManagerComponent'])
table.insert(ocp1.fields, fieldDefs['ocaFirmwareManagerImageId'])
table.insert(ocp1.fields, fieldDefs['ocaFirmwareManagerImageData'])
table.insert(ocp1.fields, fieldDefs['ocaFirmwareManagerVerifyData'])
table.insert(ocp1.fields, fieldDefs['ocaFirmwareManagerServerAddress'])
table.insert(ocp1.fields, fieldDefs['ocaFirmwareManagerUpdateFileName'])

-- dissector for OcaFirmwareManager GetComponentVersions response
function OcaFirmwareManagerGetComponentVersions(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaFirmwareManager.GetComponentVersions")
    OcaList(parameters, fieldDefs["ocaFirmwareManagerComponentVersion"], OcaVersion, classtree)
end

-- dissector for OcaFirmwareManager StartUpdateProcess response
function OcaFirmwareManagerStartUpdateProcess(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaFirmwareManager.StartUpdateProcess")
end

-- dissector for OcaFirmwareManager BeginActiveImageUpdate response
function OcaFirmwareManagerBeginActiveImageUpdate(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaFirmwareManager.BeginActiveImageUpdate")
end

-- dissector for OcaFirmwareManager AddImageData response
function OcaFirmwareManagerAddImageData(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaFirmwareManager.AddImageData")
end

-- dissector for OcaFirmwareManager VerifyImage response
function OcaFirmwareManagerVerifyImage(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaFirmwareManager.VerifyImage")
end

-- dissector for OcaFirmwareManager EndActiveImageUpdate response
function OcaFirmwareManagerEndActiveImageUpdate(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaFirmwareManager.EndActiveImageUpdate")
end

-- dissector for OcaFirmwareManager BeginPassiveComponentUpdate response
function OcaFirmwareManagerBeginPassiveComponentUpdate(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaFirmwareManager.BeginPassiveComponentUpdate")
end

-- dissector for OcaFirmwareManager EndUpdateProcess response
function OcaFirmwareManagerEndUpdateProcess(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaFirmwareManager.EndUpdateProcess")
end

-- dissector for OcaFirmwareManager object
function OcaFirmwareManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 3
    then
        responseDissector = OcaManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 3
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaFirmwareManager.GetComponentVersions")
            -- no parameters to be decoded
            responseDissector = OcaFirmwareManagerGetComponentVersions
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaFirmwareManager.StartUpdateProcess")
            -- no parameters to be decoded
            responseDissector = OcaFirmwareManagerStartUpdateProcess
        elseif methodIndex == 3
        then
            local classtree = subtree:add("OcaFirmwareManager.BeginActiveImageUpdate")
            classtree:add(fieldDefs['ocaFirmwareManagerComponent'], parameters(0, 2))
            responseDissector = OcaFirmwareManagerBeginActiveImageUpdate
        elseif methodIndex == 4
        then
            local classtree = subtree:add("OcaFirmwareManager.AddImageData")
            classtree:add(fieldDefs['ocaFirmwareManagerImageId'], parameters(0, 4))
            OcaBlob(parameters(4):tvb(), fieldDefs['ocaFirmwareManagerImageData'], classtree)
            responseDissector = OcaFirmwareManagerAddImageData
        elseif methodIndex == 5
        then
            local classtree = subtree:add("OcaFirmwareManager.VerifyImage")
            OcaBlob(parameters(0):tvb(), fieldDefs['ocaFirmwareManagerVerifyData'], classtree)
            responseDissector = OcaFirmwareManagerVerifyImage
        elseif methodIndex == 6
        then
            local classtree = subtree:add("OcaFirmwareManager.EndActiveImageUpdate")
            -- no parameters to be decoded
            responseDissector = OcaFirmwareManagerEndActiveImageUpdate
        elseif methodIndex == 7
        then
            local classtree = subtree:add("OcaFirmwareManager.BeginPassiveComponentUpdate")
            classtree:add(fieldDefs['ocaFirmwareManagerComponent'], parameters(0, 2))
            local serverAddressLength = OcaNetworkAddress(parameters(2):tvb(), fieldDefs['ocaFirmwareManagerServerAddress'], classtree)
            OcaString(parameters(2 + serverAddressLength):tvb(), fieldDefs['ocaFirmwareManagerUpdateFileName'], classtree)
            responseDissector = OcaFirmwareManagerBeginPassiveComponentUpdate
        elseif methodIndex == 8
        then
            local classtree = subtree:add("OcaFirmwareManager.EndUpdateProcess")
            -- no parameters to be decoded
            responseDissector = OcaFirmwareManagerEndUpdateProcess
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end

fixedObjectDissector[3] = OcaFirmwareManager

-----------------------------------------------------------------------
-- OcaSubscriptionManager
-----------------------------------------------------------------------

-- message fields for OcaSubscriptionManager methods
fieldDefs['ocaSubscriptionManagerEvent'] = ProtoField.bytes("ocp.1.subscrman.event", "Event")
fieldDefs['ocaSubscriptionManagerSubscriber'] = ProtoField.bytes("ocp.1.subscrman.subscriber", "Subscriber")
fieldDefs['ocaSubscriptionManagerContext'] = ProtoField.bytes("ocp.1.subscrman.context", "Context")
fieldDefs['ocaSubscriptionManagerDeliveryMode'] = ProtoField.uint8("ocp.1.subscrman.delmode", "Delivery Mode", base.DEC, ocaNotificationDeliveryModeToString)
fieldDefs['ocaSubscriptionManagerDestinationInfo'] = ProtoField.bytes("ocp.1.subscrman.destinf", "Destination Info")
table.insert(ocp1.fields, fieldDefs['ocaSubscriptionManagerEvent'])
table.insert(ocp1.fields, fieldDefs['ocaSubscriptionManagerSubscriber'])
table.insert(ocp1.fields, fieldDefs['ocaSubscriptionManagerContext'])
table.insert(ocp1.fields, fieldDefs['ocaSubscriptionManagerDeliveryMode'])
table.insert(ocp1.fields, fieldDefs['ocaSubscriptionManagerDestinationInfo'])

-- dissector for OcaSubscriptionManager AddSubscription response
function OcaSubscriptionManagerAddSubscription(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaSubscriptionManager.AddSubscription")
end

-- dissector for OcaSubscriptionManager RemoveSubscription response
function OcaSubscriptionManagerRemoveSubscription(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaSubscriptionManager.RemoveSubscription")
end

-- dissector for OcaSubscriptionManager DisableNotifications response
function OcaSubscriptionManagerDisableNotifications(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaSubscriptionManager.DisableNotifications")
end

-- dissector for OcaSubscriptionManager ReEnableNotifications response
function OcaSubscriptionManagerReEnableNotifications(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaSubscriptionManager.ReEnableNotifications")
end

-- dissector for OcaSubscriptionManager object
function OcaSubscriptionManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 3
    then
        responseDissector = OcaManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 3
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaSubscriptionManager.AddSubscription")
            local eventLength = OcaEvent(parameters(0):tvb(), fieldDefs['ocaSubscriptionManagerEvent'], classtree)
            local subscriberLength = OcaMethod(parameters(eventLength):tvb(), fieldDefs['ocaSubscriptionManagerSubscriber'], classtree)
            local contextLength = OcaBlob(parameters(eventLength + subscriberLength):tvb(), fieldDefs['ocaSubscriptionManagerContext'], classtree)
            classtree:add(fieldDefs['ocaSubscriptionManagerDeliveryMode'], parameters(eventLength + subscriberLength + contextLength, 1))
            OcaNetworkAddress(parameters(eventLength + subscriberLength + contextLength + 1):tvb(), fieldDefs['ocaSubscriptionManagerDestinationInfo'], classtree)
            responseDissector = OcaSubscriptionManagerAddSubscription
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaSubscriptionManager.RemoveSubscription")
            local eventLength = OcaEvent(parameters(0):tvb(), fieldDefs['ocaSubscriptionManagerEvent'], classtree)
            OcaMethod(parameters(eventLength):tvb(), fieldDefs['ocaSubscriptionManagerSubscriber'], classtree)
            responseDissector = OcaSubscriptionManagerRemoveSubscription
        elseif methodIndex == 3
        then
            local classtree = subtree:add("OcaSubscriptionManager.DisableNotifications")
            -- no parameters to be decoded
            responseDissector = OcaSubscriptionManagerDisableNotifications
        elseif methodIndex == 4
        then
            local classtree = subtree:add("OcaSubscriptionManager.ReEnableNotifications")
            -- no parameters to be decoded
            responseDissector = OcaSubscriptionManagerReEnableNotifications
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end

fixedObjectDissector[4] = OcaSubscriptionManager

-----------------------------------------------------------------------
-- OcaPowerManager
-----------------------------------------------------------------------

-- message fields for OcaPowerManager methods
fieldDefs['ocaPowerManagerPowerState'] = ProtoField.uint8("ocp.1.powman.powstate", "Power State", base.DEC, ocaPowerStateToString)
fieldDefs['ocaPowerManagerPowerSupply'] = ProtoField.uint32("ocp.1.powman.psu", "Power Supply", base.DEC)
fieldDefs['ocaPowerManagerOldPsu'] = ProtoField.uint32("ocp.1.powman.psu.old", "Old Power Supply", base.DEC)
fieldDefs['ocaPowerManagerNewPsu'] = ProtoField.uint32("ocp.1.powman.psu.new", "New Power Supply", base.DEC)
fieldDefs['ocaPowerManagerPowerOffOld'] = ProtoField.uint8("ocp.1.powman.psu.new", "Power Off Old Supply", base.DEC, boolToYesNoString)
fieldDefs['ocaPowerManagerAutoState'] = ProtoField.uint8("ocp.1.powman.autostate", "Auto State", base.DEC, boolToYesNoString)
table.insert(ocp1.fields, fieldDefs['ocaPowerManagerPowerState'])
table.insert(ocp1.fields, fieldDefs['ocaPowerManagerPowerSupply'])
table.insert(ocp1.fields, fieldDefs['ocaPowerManagerOldPsu'])
table.insert(ocp1.fields, fieldDefs['ocaPowerManagerNewPsu'])
table.insert(ocp1.fields, fieldDefs['ocaPowerManagerPowerOffOld'])
table.insert(ocp1.fields, fieldDefs['ocaPowerManagerAutoState'])

-- dissector for OcaPowerManager GetState response
function OcaPowerManagerGetState(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaPowerManager.GetState")
    classtree:add(fieldDefs['ocaPowerManagerPowerState'], parameters(0, 1))
end

-- dissector for OcaPowerManager SetState response
function OcaPowerManagerSetState(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaPowerManager.SetState")
end

-- dissector for OcaPowerManager GetPowerSupplies response
function OcaPowerManagerGetPowerSupplies(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaPowerManager.GetPowerSupplies")
    OcaList(parameters, fieldDefs['ocaPowerManagerPowerSupply'], OcaONo, classtree)
end

-- dissector for OcaPowerManager GetActivePowerSupplies response
function OcaPowerManagerGetActivePowerSupplies(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaPowerManager.GetActivePowerSupplies")
    OcaList(parameters, fieldDefs['ocaPowerManagerPowerSupply'], OcaONo, classtree)
end

-- dissector for OcaPowerManager ExchangePowerSupply response
function OcaPowerManagerExchangePowerSupply(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaPowerManager.ExchangePowerSupply")
end

-- dissector for OcaPowerManager GetAutoState response
function OcaPowerManagerGetAutoState(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaPowerManager.GetAutoState")
    classtree:add(fieldDefs['ocaPowerManagerAutoState'], parameters(0, 1))
end

-- dissector for OcaPowerManager object
function OcaPowerManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 3
    then
        responseDissector = OcaManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 3
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaPowerManager.GetState")
            -- no parameters to be decoded
            responseDissector = OcaPowerManagerGetState
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaPowerManager.SetState")
            classtree:add(fieldDefs['ocaPowerManagerPowerState'], parameters(0, 1))
            responseDissector = OcaPowerManagerSetState
        elseif methodIndex == 3
        then
            local classtree = subtree:add("OcaPowerManager.GetPowerSupplies")
            -- no parameters to be decoded
            responseDissector = OcaPowerManagerGetPowerSupplies
        elseif methodIndex == 4
        then
            local classtree = subtree:add("OcaPowerManager.GetActivePowerSupplies")
            -- no parameters to be decoded
            responseDissector = OcaPowerManagerGetActivePowerSupplies
        elseif methodIndex == 5
        then
            local classtree = subtree:add("OcaPowerManager.ExchangePowerSupply")
            OcaONo(parameters(0, 4):tvb(), fieldDefs['ocaPowerManagerOldPsu'], classTree);
            OcaONo(parameters(4, 4):tvb(), fieldDefs['ocaPowerManagerNewPsu'], classTree);
            classtree:add(fieldDefs['ocaPowerManagerPowerOffOld'], parameters(8, 1))
            responseDissector = OcaPowerManagerExchangePowerSupply
        elseif methodIndex == 6
        then
            local classtree = subtree:add("OcaPowerManager.GetAutoState")
            -- no parameters to be decoded
            responseDissector = OcaPowerManagerGetAutoState
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end

fixedObjectDissector[5] = OcaPowerManager

-----------------------------------------------------------------------
-- OcaNetworkManager
-----------------------------------------------------------------------

-- message fields for OcaNetworkManager methods
fieldDefs['ocaNetworkManagerNetwork'] = ProtoField.uint32("ocp.1.netwman.network", "Network", base.DEC)
table.insert(ocp1.fields, fieldDefs['ocaNetworkManagerNetwork'])

-- dissector for OcaNetworkManager GetNetworks response
function OcaNetworkManagerGetNetworks(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaNetworkManager.GetNetworks")
    OcaList(parameters, fieldDefs['ocaNetworkManagerNetwork'], OcaONo, classtree)
end

-- dissector for OcaNetworkManager GetStreamNetworks response
function OcaNetworkManagerGetStreamNetworks(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaNetworkManager.GetStreamNetworks")
    OcaList(parameters, fieldDefs['ocaNetworkManagerNetwork'], OcaONo, classtree)
end

-- dissector for OcaNetworkManager GetControlNetworks response
function OcaNetworkManagerGetControlNetworks(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaNetworkManager.GetControlNetworks")
    OcaList(parameters, fieldDefs['ocaNetworkManagerNetwork'], OcaONo, classtree)
end

-- dissector for OcaNetworkManager GetMediaTransportNetworks response
function OcaNetworkManagerGetMediaTransportNetworks(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaNetworkManager.GetMediaTransportNetworks")
    OcaList(parameters, fieldDefs['ocaNetworkManagerNetwork'], OcaONo, classtree)
end

-- dissector for OcaNetworkManager object
function OcaNetworkManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 3
    then
        responseDissector = OcaManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 3
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaNetworkManager.GetNetworks")
            -- no parameters to be decoded
            responseDissector = OcaNetworkManagerGetNetworks
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaNetworkManager.GetStreamNetworks")
            -- no parameters to be decoded
            responseDissector = OcaNetworkManagerGetStreamNetworks
        elseif methodIndex == 3
        then
            local classtree = subtree:add("OcaNetworkManager.GetControlNetworks")
            -- no parameters to be decoded
            responseDissector = OcaNetworkManagerGetControlNetworks
        elseif methodIndex == 4
        then
            local classtree = subtree:add("OcaNetworkManager.GetMediaTransportNetworks")
            -- no parameters to be decoded
            responseDissector = OcaNetworkManagerGetMediaTransportNetworks
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end

fixedObjectDissector[6] = OcaNetworkManager

-----------------------------------------------------------------------
-- OcaMediaClockManager
-----------------------------------------------------------------------

-- message fields for OcaMediaClockManager methods
fieldDefs['ocaMediaClockManagerClock'] = ProtoField.uint32("ocp.1.mclkman.clock", "Clock", base.DEC)
fieldDefs['ocaMediaClockManagerMediaClockType'] = ProtoField.uint8("ocp.1.mclkman.type", "Clock type", base.DEC, ocaMediaClockTypeToString)
table.insert(ocp1.fields, fieldDefs['ocaMediaClockManagerClock'])
table.insert(ocp1.fields, fieldDefs['ocaMediaClockManagerMediaClockType'])

-- dissector for OcaMediaClockManager GetClocks response
function OcaMediaClockManagerGetClocks(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaMediaClockManager.GetClocks")
    OcaList(parameters, fieldDefs['ocaMediaClockManagerClock'], OcaONo, subtree)
end

-- dissector for OcaMediaClockManager GetMediaClockTypesSupported response
function OcaMediaClockManagerGetMediaClockTypesSupported(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaMediaClockManager.GetMediaClockTypesSupported")
    OcaList(parameters, fieldDefs['ocaMediaClockManagerMediaClockType'], OcaEnumeration, subtree)
end

-- dissector for OcaMediaClockManager GetClock3s response
function OcaMediaClockManagerGetClock3s(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaMediaClockManager.GetClock3s")
    OcaList(parameters, fieldDefs['ocaMediaClockManagerClock'], OcaONo, subtree)
end

-- dissector for OcaMediaClockManager object
function OcaMediaClockManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 3
    then
        responseDissector = OcaManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 3
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaMediaClockManager.GetClocks")
            -- no parameters to be decoded
            responseDissector = OcaMediaClockManagerGetClocks
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaMediaClockManager.GetMediaClockTypesSupported")
            -- no parameters to be decoded
            responseDissector = OcaMediaClockManagerGetMediaClockTypesSupported
        elseif methodIndex == 3
        then
            local classtree = subtree:add("OcaMediaClockManager.GetClock3s")
            -- no parameters to be decoded
            responseDissector = OcaMediaClockManagerGetClock3s
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end

fixedObjectDissector[7] = OcaMediaClockManager

-----------------------------------------------------------------------
-- OcaLibraryManager
-----------------------------------------------------------------------

-- message fields for OcaLibraryManager methods
fieldDefs['ocaLibraryManagerLibraryVolumeType'] = ProtoField.bytes("ocp.1.libman.libvoltype", "Library Volume Type")
fieldDefs['ocaLibraryManagerLibraryId'] = ProtoField.uint32("ocp.1.libman.libid", "Library ID", base.DEC)
fieldDefs['ocaLibraryManagerLibraryCount'] = ProtoField.uint16("ocp.1.libman.libcnt", "Library Count", base.DEC)
fieldDefs['ocaLibraryManagerLibrary'] = ProtoField.uint32("ocp.1.libman.lib", "Library", base.DEC)
fieldDefs['ocaLibraryManagerPatch'] = ProtoField.bytes("ocp.1.libman.patch", "Patch")
table.insert(ocp1.fields, fieldDefs['ocaLibraryManagerLibraryVolumeType'])
table.insert(ocp1.fields, fieldDefs['ocaLibraryManagerLibraryId'])
table.insert(ocp1.fields, fieldDefs['ocaLibraryManagerLibraryCount'])
table.insert(ocp1.fields, fieldDefs['ocaLibraryManagerLibrary'])
table.insert(ocp1.fields, fieldDefs['ocaLibraryManagerPatch'])

-- dissector for OcaLibraryManager AddLibrary response
function OcaLibraryManagerAddLibrary(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaLibraryManager.AddLibrary")
    OcaONo(buf(0):tvb(), fieldDefs['ocaLibraryManagerLibraryId'], classTree);
end

-- dissector for OcaLibraryManager DeleteLibrary response
function OcaLibraryManagerDeleteLibrary(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaLibraryManager.DeleteLibrary")
end

-- dissector for OcaLibraryManager GetLibraryCount response
function OcaLibraryManagerGetLibraryCount(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaLibraryManager.GetLibraryCount")
    classtree:add(fieldDefs['ocaLibraryManagerLibraryCount'], parameters(0, 2))
end

-- dissector for OcaLibraryManager GetLibraryList response
function OcaLibraryManagerGetLibraryList(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaLibraryManager.GetLibraryList")
    OcaList(parameters, fieldDefs['ocaLibraryManagerLibrary'], OcaONo, classtree)
end

-- dissector for OcaLibraryManager GetCurrentPatch response
function OcaLibraryManagerGetCurrentPatch(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaLibraryManager.GetCurrentPatch")
    OcaLibVolIdentifier(parameters(0):tvb(), fieldDefs['ocaLibraryManagerPatch'], classtree)
end

-- dissector for OcaLibraryManager ApplyPatch response
function OcaLibraryManagerApplyPatch(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaLibraryManager.ApplyPatch")
end

-- dissector for OcaLibraryManager object
function OcaLibraryManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 3
    then
        responseDissector = OcaManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 3
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaLibraryManager.AddLibrary")
            OcaLibVolType(parameters(0):tvb(), fieldDefs['ocaLibraryManagerLibraryVolumeType'])
            responseDissector = OcaLibraryManagerAddLibrary
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaLibraryManager.DeleteLibrary")
            OcaONo(parameters(0):tvb(), fieldDefs['ocaLibraryManagerLibraryId'], classTree);
            responseDissector = OcaLibraryManagerDeleteLibrary
        elseif methodIndex == 3
        then
            local classtree = subtree:add("OcaLibraryManager.GetLibraryCount")
            classtree:add(fieldDefs['ocaLibraryManagerLibraryVolumeType'], parameters(0, 1))
            responseDissector = OcaLibraryManagerGetLibraryCount
        elseif methodIndex == 4
        then
            local classtree = subtree:add("OcaLibraryManager.GetLibraryList")
            classtree:add(fieldDefs['ocaLibraryManagerLibraryVolumeType'], parameters(0, 1))
            responseDissector = OcaLibraryManagerGetLibraryList
        elseif methodIndex == 5
        then
            local classtree = subtree:add("OcaLibraryManager.GetCurrentPatch")
            -- no parameters to be decoded
            responseDissector = OcaLibraryManagerGetCurrentPatch
        elseif methodIndex == 6
        then
            local classtree = subtree:add("OcaLibraryManager.ApplyPatch")
            OcaLibVolIdentifier(parameters(0):tvb(), fieldDefs['ocaLibraryManagerPatch'], classtree)
            responseDissector = OcaLibraryManagerApplyPatch
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end

fixedObjectDissector[8] = OcaLibraryManager

-----------------------------------------------------------------------
-- OcaAudioProcessingManager
-----------------------------------------------------------------------

-- message fields for OcaAudioProcessingManager methods
fieldDefs['ocaAudioProcessingManagerHeadroom'] = ProtoField.float("ocp.1.aupman.headroom", "Headroom")
table.insert(ocp1.fields, fieldDefs['ocaAudioProcessingManagerHeadroom'])

-- dissector for OcaAudioProcessingManager GetHeadroom response
function OcaAudioProcessingManagerGetHeadroom(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaAudioProcessingManager.GetHeadroom")
    classtree:add(fieldDefs['ocaAudioProcessingManagerHeadroom'], parameters(0, 4)):append_text(" dB")
end

-- dissector for OcaAudioProcessingManager SetHeadroom response
function OcaAudioProcessingManagerSetHeadroom(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaAudioProcessingManager.SetHeadroom")
end

-- dissector for OcaAudioProcessingManager object
function OcaAudioProcessingManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 3
    then
        responseDissector = OcaManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 3
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaAudioProcessingManager.GetHeadroom")
            -- no parameters to be decoded
            responseDissector = OcaAudioProcessingManagerGetHeadroom
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaAudioProcessingManager.SetHeadroom")
            classtree:add(fieldDefs['ocaAudioProcessingManagerHeadroom'], parameters(0, 4)):append_text(" dB")
            responseDissector = OcaAudioProcessingManagerSetHeadroom
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end

fixedObjectDissector[9] = OcaAudioProcessingManager

-----------------------------------------------------------------------
-- OcaDeviceTimeManager
-----------------------------------------------------------------------

-- message fields for OcaDeviceTimeManager methods
fieldDefs['ocaDeviceTimeManagerDeviceTimeNTP'] = ProtoField.uint64("ocp.1.timman.timentp", "Device Time (NTP)")
fieldDefs['ocaDeviceTimeManagerTimeSource'] = ProtoField.uint32("ocp.1.timman.timsrc", "Time Source", base.DEC)
fieldDefs['ocaDeviceTimeManagerDeviceTimePTP'] = ProtoField.bytes("ocp.1.timman.timeptp", "Device Time (PTP)")
table.insert(ocp1.fields, fieldDefs['ocaDeviceTimeManagerDeviceTimeNTP'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceTimeManagerTimeSource'])
table.insert(ocp1.fields, fieldDefs['ocaDeviceTimeManagerDeviceTimePTP'])

-- dissector for OcaDeviceTimeManager GetDeviceTimeNTP response
function OcaDeviceTimeManagerGetDeviceTimeNTP(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceTimeManager.GetDeviceTimeNTP")
    OcaTimeNTP(parameters(0):tvb(), fieldDefs['ocaDeviceTimeManagerDeviceTimeNTP'], classtree)
end

-- dissector for OcaDeviceTimeManager SetDeviceTimeNTP response
function OcaDeviceTimeManagerSetDeviceTimeNTP(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceTimeManager.SetDeviceTimeNTP")
end

-- dissector for OcaDeviceTimeManager GetTimeSources response
function OcaDeviceTimeManagerGetTimeSources(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceTimeManager.GetTimeSources")
    OcaList(parameters, fieldDefs['ocaDeviceTimeManagerTimeSource'], OcaONo, subtree)
end

-- dissector for OcaDeviceTimeManager GetCurrentDeviceTimeSource response
function OcaDeviceTimeManagerGetCurrentDeviceTimeSource(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceTimeManager.GetCurrentDeviceTimeSource")
    OcaONo(parameters(0):tvb(), fieldDefs['ocaDeviceTimeManagerTimeSource'], classtree)
end

-- dissector for OcaDeviceTimeManager SetCurrentDeviceTimeSource response
function OcaDeviceTimeManagerSetCurrentDeviceTimeSource(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceTimeManager.SetCurrentDeviceTimeSource")
end

-- dissector for OcaDeviceTimeManager GetDeviceTimePTP response
function OcaDeviceTimeManagerGetDeviceTimePTP(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceTimeManager.GetDeviceTimePTP")
    OcaTimePTP(parameters(0):tvb(), fieldDefs['ocaDeviceTimeManagerDeviceTimePTP'], classtree)
end

-- dissector for OcaDeviceTimeManager SetDeviceTimePTP response
function OcaDeviceTimeManagerSetDeviceTimePTP(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaDeviceTimeManager.SetDeviceTimePTP")
end

-- dissector for OcaDeviceTimeManager object
function OcaDeviceTimeManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 3
    then
        responseDissector = OcaManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 3
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaDeviceTimeManager.GetDeviceTimeNTP")
            -- no parameters to be decoded
            responseDissector = OcaDeviceTimeManagerGetDeviceTimeNTP
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaDeviceTimeManager.SetDeviceTimeNTP")
            OcaTimeNTP(parameters(0):tvb(), fieldDefs['ocaDeviceTimeManagerDeviceTimeNTP'], classtree)
            responseDissector = OcaDeviceTimeManagerSetDeviceTimeNTP
        elseif methodIndex == 3
        then
            local classtree = subtree:add("OcaDeviceTimeManager.GetTimeSources")
            -- no parameters to be decoded
            responseDissector = OcaDeviceTimeManagerGetTimeSources
        elseif methodIndex == 4
        then
            local classtree = subtree:add("OcaDeviceTimeManager.GetCurrentDeviceTimeSource")
            -- no parameters to be decoded
            responseDissector = OcaDeviceTimeManagerGetCurrentDeviceTimeSource
        elseif methodIndex == 5
        then
            local classtree = subtree:add("OcaDeviceTimeManager.SetCurrentDeviceTimeSource")
            OcaONo(parameters(0):tvb(), fieldDefs['ocaDeviceTimeManagerTimeSource'], classtree)
            responseDissector = OcaDeviceTimeManagerSetCurrentDeviceTimeSource
        elseif methodIndex == 6
        then
            local classtree = subtree:add("OcaDeviceTimeManager.GetDeviceTimePTP")
            -- no parameters to be decoded
            responseDissector = OcaDeviceTimeManagerGetDeviceTimePTP
        elseif methodIndex == 7
        then
            local classtree = subtree:add("OcaDeviceTimeManager.SetDeviceTimePTP")
            OcaTimePTP(parameters(0):tvb(), fieldDefs['ocaDeviceTimeManagerDeviceTimePTP'], classtree)
            responseDissector = OcaDeviceTimeManagerSetDeviceTimePTP
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end

fixedObjectDissector[10] = OcaDeviceTimeManager

-----------------------------------------------------------------------
-- OcaCodingManager
-----------------------------------------------------------------------

-- message fields for OcaCodingManager methods
fieldDefs['ocaCodingManagerSchemeID'] = ProtoField.uint16("ocp.1.codman.sid", "Scheme ID")
fieldDefs['ocaCodingManagerScheme'] = ProtoField.string("ocp.1.codmam.scheme", "Scheme", base.UNICODE)
table.insert(ocp1.fields, fieldDefs['ocaCodingManagerSchemeID'])
table.insert(ocp1.fields, fieldDefs['ocaCodingManagerScheme'])

-- dissector for OcaCodingManager GetAvailableEncodingSchemes response
function OcaCodingManagerGetAvailableEncodingSchemes(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaCodingManager.GetAvailableEncodingSchemes")
    OcaMap(parameters, fieldDefs['ocaCodingManagerSchemeID'], OcaMediaCodingSchemeID, fieldDefs['ocaCodingManagerScheme'], OcaString, classtree)
end

-- dissector for OcaCodingManager GetAvailableDecodingSchemes response
function OcaCodingManagerGetAvailableDecodingSchemes(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaCodingManager.GetAvailableDecodingSchemes")
    OcaMap(parameters, fieldDefs['ocaCodingManagerSchemeID'], OcaMediaCodingSchemeID, fieldDefs['ocaCodingManagerScheme'], OcaString, classtree)
end

-- dissector for OcaCodingManager object
function OcaCodingManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 3
    then
        responseDissector = OcaManager(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 3
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaCodingManager.GetAvailableEncodingSchemes")
            -- no parameters to be decoded
            responseDissector = OcaCodingManagerGetAvailableEncodingSchemes
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaCodingManager.GetAvailableDecodingSchemes")
            -- no parameters to be decoded
            responseDissector = OcaCodingManagerGetAvailableDecodingSchemes
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end

fixedObjectDissector[12] = OcaCodingManager


-----------------------------------------------------------------------
-- DISSECTORS FOR OCA WORKERS
-----------------------------------------------------------------------

-----------------------------------------------------------------------
-- OcaWorker
-----------------------------------------------------------------------

-- message fields for OcaWorker methods
fieldDefs['ocaWorkerEnabled'] = ProtoField.uint8("ocp.1.worker.enabled", "Enabled", base.DEC, boolToYesNoString)
fieldDefs['ocaWorkerPortLabel'] = ProtoField.string("ocp.1.worker.portlabel", "Port Label", base.UNICODE)
fieldDefs['ocaWorkerPortMode'] = ProtoField.uint8("ocp.1.worker.portmode", "Port Mode", base.DEC, ocaPortModeToString)
fieldDefs['ocaWorkerPortID'] = ProtoField.bytes("ocp.1.worker.portid", "Port ID")
fieldDefs['ocaWorkerPort'] = ProtoField.bytes("ocp.1.worker.port", "Port")
fieldDefs['ocaWorkerPortName'] = ProtoField.string("ocp.1.worker.portname", "Port Name", base.UNICODE)
fieldDefs['ocaWorkerLabel'] = ProtoField.string("ocp.1.worker.label", "Label", base.UNICODE)
fieldDefs['ocaWorkerOwner'] = ProtoField.uint32("ocp.1.worker.owner", "Owner", base.DEC)
fieldDefs['ocaWorkerLatency'] = ProtoField.float("ocp.1.worker.latency", "Latency")
fieldDefs['ocaWorkerNamePathName'] = ProtoField.string("ocp.1.worker.path.name", "Name", base.UNICODE)
fieldDefs['ocaWorkerONoPathONo'] = ProtoField.uint32("ocp.1.worker.path.ono", "Object number", base.DEC)
table.insert(ocp1.fields, fieldDefs['ocaWorkerEnabled'])
table.insert(ocp1.fields, fieldDefs['ocaWorkerPortLabel'])
table.insert(ocp1.fields, fieldDefs['ocaWorkerPortMode'])
table.insert(ocp1.fields, fieldDefs['ocaWorkerPortID'])
table.insert(ocp1.fields, fieldDefs['ocaWorkerPort'])
table.insert(ocp1.fields, fieldDefs['ocaWorkerPortName'])
table.insert(ocp1.fields, fieldDefs['ocaWorkerLabel'])
table.insert(ocp1.fields, fieldDefs['ocaWorkerOwner'])
table.insert(ocp1.fields, fieldDefs['ocaWorkerLatency'])
table.insert(ocp1.fields, fieldDefs['ocaWorkerNamePathName'])
table.insert(ocp1.fields, fieldDefs['ocaWorkerONoPathONo'])

-- dissector for OcaWorker GetEnabled response
function OcaWorkerGetEnabled(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaWorker.GetEnabled")
    classtree:add(fieldDefs['ocaWorkerEnabled'], parameters(0, 1))
end

-- dissector for OcaWorker SetEnabled response
function OcaWorkerSetEnabled(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaWorker.SetEnabled")
end

-- dissector for OcaWorker AddPort response
function OcaWorkerAddPort(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaWorker.AddPort")
    OcaPortID(parameters(0):tvb(), fieldDefs['ocaWorkerPortID'], classtree)
end

-- dissector for OcaWorker DeletePort response
function OcaWorkerDeletePort(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaWorker.DeletePort")
end

-- dissector for OcaWorker GetPorts response
function OcaWorkerGetPorts(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaWorker.GetPorts")
    OcaList(parameters, fieldDefs['ocaWorkerPort'], OcaPort, classtree)
end

-- dissector for OcaWorker GetPortName response
function OcaWorkerGetPortName(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaWorker.GetPortName")
    OcaString(parameters(0):tvb(), fieldDefs['ocaWorkerPortName'], classtree)
end

-- dissector for OcaWorker SetPortName response
function OcaWorkerSetPortName(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaWorker.SetPortName")
end

-- dissector for OcaWorker GetLabel response
function OcaWorkerGetLabel(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaWorker.GetLabel")
    OcaString(parameters(0):tvb(), fieldDefs['ocaWorkerLabel'], classtree)
end

-- dissector for OcaWorker SetLabel response
function OcaWorkerSetLabel(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaWorker.SetLabel")
end

-- dissector for OcaWorker GetOwner response
function OcaWorkerGetOwner(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaWorker.GetOwner")
    OcaONo(parameters(0):tvb(), fieldDefs['ocaWorkerOwner'], classtree);
end

-- dissector for OcaWorker GetLatency response
function OcaWorkerGetLatency(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaWorker.GetLatency")
    classtree:add(fieldDefs['ocaWorkerLatency'], parameters(0, 4)):append_text(" seconds")
end

-- dissector for OcaWorker SetLatency response
function OcaWorkerSetLatency(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaWorker.SetLatency")
end

-- dissector for OcaWorker GetPath response
function OcaWorkerGetPath(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaWorker.GetPath")
    local nametree = classtree:add("Name path")
    OcaList(parameters, fieldDefs['ocaWorkerNamePathName'], OcaString, nametree)
    local onotree = classtree:add("Object number path")
    OcaList(parameters, fieldDefs['ocaWorkerONoPathONo'], OcaONo, onotree)
end

-- dissector for OcaWorker object
function OcaWorker(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 2
    then
        responseDissector = OcaRoot(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 2
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaWorker.GetEnabled")
            -- no parameters to be decoded
            responseDissector = OcaWorkerGetEnabled
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaWorker.SetEnabled")
            classtree:add(fieldDefs['ocaWorkerEnabled'], parameters(0, 1))
            responseDissector = OcaWorkerSetEnabled
        elseif methodIndex == 3
        then
            local classtree = subtree:add("OcaWorker.AddPort")
            local labelLength = OcaString(parameters(0):tvb(), fieldDefs['ocaWorkerPortLabel'], classtree)
            classtree:add(fieldDefs['ocaWorkerPortMode'], parameters(labelLength, 1))
            responseDissector = OcaWorkerAddPort
        elseif methodIndex == 4
        then
            local classtree = subtree:add("OcaWorker.DeletePort")
            OcaPortID(parameters(0):tvb(), fieldDefs['ocaWorkerPortID'], classtree)
            responseDissector = OcaWorkerDeletePort
        elseif methodIndex == 5
        then
            local classtree = subtree:add("OcaWorker.GetPorts")
            -- no parameters to be decoded
            responseDissector = OcaWorkerGetPorts
        elseif methodIndex == 6
        then
            local classtree = subtree:add("OcaWorker.GetPortName")
            OcaPortID(parameters(0):tvb(), fieldDefs['ocaWorkerPortID'], classtree)
            responseDissector = OcaWorkerGetPortName
        elseif methodIndex == 7
        then
            local classtree = subtree:add("OcaWorker.SetPortName")
            local portIDLength = OcaPortID(parameters(0):tvb(), fieldDefs['ocaWorkerPortID'], classtree)
            OcaString(parameters(portIDLength):tvb(), fieldDefs['ocaWorkerPortName'], classtree)
            responseDissector = OcaWorkerSetPortName
        elseif methodIndex == 8
        then
            local classtree = subtree:add("OcaWorker.GetLabel")
            -- no parameters to be decoded
            responseDissector = OcaWorkerGetLabel
        elseif methodIndex == 9
        then
            local classtree = subtree:add("OcaWorker.SetLabel")
            OcaString(parameters(0):tvb(), fieldDefs['ocaWorkerLabel'], classtree)
            responseDissector = OcaWorkerSetLabel
        elseif methodIndex == 10
        then
            local classtree = subtree:add("OcaWorker.GetOwner")
            -- no parameters to be decoded
            responseDissector = OcaWorkerGetOwner
        elseif methodIndex == 11
        then
            local classtree = subtree:add("OcaWorker.GetLatency")
            -- no parameters to be decoded
            responseDissector = OcaWorkerGetLatency
        elseif methodIndex == 12
        then
            local classtree = subtree:add("OcaWorker.SetLatency")
            classtree:add(fieldDefs['ocaWorkerLatency'], parameters(0, 4)):append_text(" seconds")
            responseDissector = OcaWorkerSetLatency
        elseif methodIndex == 13
        then
            local classtree = subtree:add("OcaWorker.GetPath")
            -- no parameters to be decoded
            responseDissector = OcaWorkerGetPath
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end

-----------------------------------------------------------------------
-- OcaBlock
-----------------------------------------------------------------------

-- message fields for OcaBlock methods
fieldDefs['ocaBlockType'] = ProtoField.uint32("ocp.1.block.type", "Type", base.DEC, ocaBlockTypeToString)
fieldDefs['ocaBlockClassID'] = ProtoField.bytes("ocp.1.block.classid", "Class ID")
fieldDefs['ocaBlockContructionParameters'] = ProtoField.bytes("ocp.1.block.constrparam", "Construction Parameters")
fieldDefs['ocaBlockMemberONo'] = ProtoField.uint32("ocp.1.block.memberono", "Member Object Number", base.DEC)
fieldDefs['ocaBlockFactoryONo'] = ProtoField.uint32("ocp.1.block.factoryono", "Factory Object Number", base.DEC)
fieldDefs['ocaBlockMember'] = ProtoField.bytes("ocp.1.block.member", "Member")
fieldDefs['ocaBlockBlockMember'] = ProtoField.bytes("ocp.1.block.blkmem", "Block Member")
fieldDefs['ocaBlockSignalPath'] = ProtoField.bytes("ocp.1.block.sigpath", "Signal Path")
fieldDefs['ocaBlockIndex'] = ProtoField.uint16("ocp.1.block.idx", "Index")
fieldDefs['ocaBlockParamSet'] = ProtoField.bytes("ocp.1.block.paramset", "Parameter Set")
fieldDefs['ocaBlockParamSetData'] = ProtoField.bytes("ocp.1.block.parsetdat", "Param Set Data")
fieldDefs['ocaBlockVolumeName'] = ProtoField.string("ocp.1.block.volname", "Volume Name", base.UNICODE)
fieldDefs['ocaBlockVolumeVersion'] = ProtoField.uint32("ocp.1.block.volvers", "Volume Version", base.DEC)
fieldDefs['ocaBlockGlobalType'] = ProtoField.bytes("ocp.1.block.globtype", "Global Type")
fieldDefs['ocaBlockProtoONo'] = ProtoField.uint32("ocp.1.block.protoono", "Prototype Object Number", base.DEC)
fieldDefs['ocaBlockSearchName'] = ProtoField.string("ocp.1.block.srchname", "Search Name", base.UNICODE)
fieldDefs['ocaBlockSearchPath'] = ProtoField.string("ocp.1.block.srchpath", "Search Path", base.UNICODE)
fieldDefs['ocaBlockStringComparisonType'] = ProtoField.uint8("ocp.1.block.strcomp", "String Comparison Type", base.DEC, ocaStringComparisonTypeToString)
fieldDefs['ocaBlockSearchClassID'] = ProtoField.bytes("ocp.1.block.srchclid", "Search Class ID")
fieldDefs['ocaBlockResultFlags'] = ProtoField.uint16("ocp.1.block.resflags", "Result Flags", base.HEX, ocaObjectSearchResultFlagsToString)
fieldDefs['ocaBlockSearchResult'] = ProtoField.bytes("ocp.1.block.srchres", "Result")
table.insert(ocp1.fields, fieldDefs['ocaBlockType'])
table.insert(ocp1.fields, fieldDefs['ocaBlockClassID'])
table.insert(ocp1.fields, fieldDefs['ocaBlockContructionParameters'])
table.insert(ocp1.fields, fieldDefs['ocaBlockMemberONo'])
table.insert(ocp1.fields, fieldDefs['ocaBlockFactoryONo'])
table.insert(ocp1.fields, fieldDefs['ocaBlockMember'])
table.insert(ocp1.fields, fieldDefs['ocaBlockBlockMember'])
table.insert(ocp1.fields, fieldDefs['ocaBlockSignalPath'])
table.insert(ocp1.fields, fieldDefs['ocaBlockIndex'])
table.insert(ocp1.fields, fieldDefs['ocaBlockParamSet'])
table.insert(ocp1.fields, fieldDefs['ocaBlockParamSetData'])
table.insert(ocp1.fields, fieldDefs['ocaBlockVolumeName'])
table.insert(ocp1.fields, fieldDefs['ocaBlockVolumeVersion'])
table.insert(ocp1.fields, fieldDefs['ocaBlockGlobalType'])
table.insert(ocp1.fields, fieldDefs['ocaBlockProtoONo'])
table.insert(ocp1.fields, fieldDefs['ocaBlockSearchName'])
table.insert(ocp1.fields, fieldDefs['ocaBlockSearchPath'])
table.insert(ocp1.fields, fieldDefs['ocaBlockStringComparisonType'])
table.insert(ocp1.fields, fieldDefs['ocaBlockSearchClassID'])
table.insert(ocp1.fields, fieldDefs['ocaBlockResultFlags'])
table.insert(ocp1.fields, fieldDefs['ocaBlockSearchResult'])

-- dissector for OcaBlock GetType response
function OcaBlockGetType(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.GetType")
    OcaONo(parameters(0):tvb(), fieldDefs['ocaBlockType'], classtree)
end

-- dissector for OcaBlock ConstructMember response
function OcaBlockConstructMember(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.ConstructMember")
    OcaONo(parameters(0):tvb(), fieldDefs['ocaBlockMemberONo'], classtree)
end

-- dissector for OcaBlock ConstructMemberUsingFactory response
function OcaBlockConstructMemberUsingFactory(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.ConstructMember")
    OcaONo(parameters(0):tvb(), fieldDefs['ocaBlockMemberONo'], classtree)
end

-- dissector for OcaBlock DeleteMember response
function OcaBlockDeleteMember(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.DeleteMember")
end

-- dissector for OcaBlock GetMembers response
function OcaBlockGetMembers(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.GetMembers")
    OcaList(parameters, fieldDefs['ocaBlockMember'], OcaObjectIdentification, classtree)
end

-- dissector for OcaBlock GetMembersRecursive response
function OcaBlockGetMembersRecursive(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.GetMembersRecursive")
    OcaList(parameters, fieldDefs['ocaBlockMember'], OcaBlockMember, classtree)
end

-- dissector for OcaBlock AddSignalPath response
function OcaBlockAddSignalPath(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.AddSignalPath")
    classtree:add(fieldDefs['ocaBlockIndex'], parameters(0, 2))
end

-- dissector for OcaBlock DeleteSignalPath response
function OcaBlockDeleteSignalPath(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.DeleteSignalPath")
end

-- dissector for OcaBlock GetSignalPaths response
function OcaBlockGetSignalPaths(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.GetSignalPaths")
    OcaMap(parameters, fieldDefs['ocaBlockIndex'], OcaUint16, fieldDefs['ocaBlockSignalPath'], OcaSignalPath, classtree)
end

-- dissector for OcaBlock GetSignalPathsRecursive response
function OcaBlockGetSignalPathsRecursive(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.GetSignalPathsRecursive")
    OcaMap(parameters, fieldDefs['ocaBlockIndex'], OcaUint16, fieldDefs['ocaBlockSignalPath'], OcaSignalPath, classtree)
end

-- dissector for OcaBlock GetMostRecentParamSetIdentifier response
function OcaBlockGetMostRecentParamSetIdentifier(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.GetMostRecentParamSetIdentifier")
    OcaLibVolIdentifier(parameters(0):tvb(), fieldDefs['ocaBlockParamSet'], classtree)
end

-- dissector for OcaBlock ApplyParamSet response
function OcaBlockApplyParamSet(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.ApplyParamSet")
end

-- dissector for OcaBlock GetCurrentParamSetData response
function OcaBlockGetCurrentParamSetData(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.GetCurrentParamSetData")
    OcaLibVolData_ParamSet(parameters(0):tvb(), fieldDefs['ocaBlockParamSetData'], classtree)
end

-- dissector for OcaBlock StoreCurrentParamSetData response
function OcaBlockStoreCurrentParamSetData(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.StoreCurrentParamSetData")
end

-- dissector for OcaBlock GetGlobalType response
function OcaBlockGetGlobalTypea(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.GetGlobalType")
    OcaGlobalBlockTypeIdentifier(parameters(0):tvb(), fieldDefs['ocaBlockGlobalType'], classtree)
end

-- dissector for OcaBlock GetONoMap response
function OcaBlockGetONoMap(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.GetONoMap")
    OcaMap(parameters, fieldDefs['ocaBlockProtoONo'], OcaProtoONo, fieldDefs['ocaBlockMemberONo'], OcaONo, classtree)
end

-- dissector for OcaBlock FindObjectsByRole response
function OcaBlockFindObjectsByRole(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.FindObjectsByRole")
    OcaList(parameters, fieldDefs['ocaBlockSearchResult'], OcaObjectSearchResult, classtree)
end

-- dissector for OcaBlock FindObjectsByRoleRecursive response
function OcaBlockFindObjectsByRoleRecursive(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.FindObjectsByRoleRecursive")
    OcaList(parameters, fieldDefs['ocaBlockSearchResult'], OcaObjectSearchResult, classtree)
end

-- dissector for OcaBlock FindObjectsByLabelRecursive response
function OcaBlockFindObjectsByLabelRecursive(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.FindObjectsByLabelRecursive")
    OcaList(parameters, fieldDefs['ocaBlockSearchResult'], OcaObjectSearchResult, classtree)
end

-- dissector for OcaBlock FindObjectsByPath response
function OcaBlockFindObjectsByPath(parameterCount, parameters, subtree)
    local classtree = subtree:add("OcaBlock.FindObjectsByPath")
    OcaList(parameters, fieldDefs['ocaBlockSearchResult'], OcaObjectSearchResult, classtree)
end

-- dissector for OcaBlock object
function OcaBlock(defLevel, methodIndex, parameterCount, parameters, subtree)
    local responseDissector = nil

    if defLevel < 3
    then
        responseDissector = OcaWorker(defLevel, methodIndex, parameterCount, parameters, subtree)
    elseif defLevel == 3
    then
        if methodIndex == 1
        then
            local classtree = subtree:add("OcaBlock.GetType")
            -- no parameters to be decoded
            responseDissector = OcaBlockGetType
        elseif methodIndex == 2
        then
            local classtree = subtree:add("OcaBlock.ConstructMember")
            local classIDLength = OcaClassID(parameters(0):tvb(), fieldDefs['ocaBlockClassID'], classtree);
            classtree:add(fieldDefs['ocaBlockConstructionParameters'], parameters(classIDLength));
            responseDissector = OcaBlockConstructMember
        elseif methodIndex == 3
        then
            local classtree = subtree:add("OcaBlock.ConstructMemberUsingFactory")
            OcaONo(parameters(0):tvb(), fieldDefs['ocaBlockFactoryONo'], classtree)
            responseDissector = OcaBlockConstructMemberUsingFactory
        elseif methodIndex == 4
        then
            local classtree = subtree:add("OcaBlock.DeleteMember")
            OcaONo(parameters(0):tvb(), fieldDefs['ocaBlockFactoryMember'], classtree)
            responseDissector = OcaBlockDeleteMember
        elseif methodIndex == 5
        then
            local classtree = subtree:add("OcaBlock.GetMembers")
            -- no parameters to be decoded
            responseDissector = OcaBlockGetMembers
        elseif methodIndex == 6
        then
            local classtree = subtree:add("OcaBlock.GetMembersRecursive")
            -- no parameters to be decoded
            responseDissector = OcaBlockGetMembersRecursive
        elseif methodIndex == 7
        then
            local classtree = subtree:add("OcaBlock.AddSignalPath")
            OcaSignalPath(parameters(0):tvb(), fieldDefs['ocaBlockSignalPath'], classtree)
            responseDissector = OcaBlockAddSignalPath
        elseif methodIndex == 8
        then
            local classtree = subtree:add("OcaBlock.DeleteSignalPath")
            classtree:add(fieldDefs['ocaBlockIndex'], parameters(0, 2));
            responseDissector = OcaBlockDeleteSignalPath
        elseif methodIndex == 9
        then
            local classtree = subtree:add("OcaBlock.GetSignalPaths")
            -- no parameters to be decoded
            responseDissector = OcaBlockGetSignalPaths
        elseif methodIndex == 10
        then
            local classtree = subtree:add("OcaBlock.GetSignalPathsRecursive")
            -- no parameters to be decoded
            responseDissector = OcaBlockGetSignalPathsRecursive
        elseif methodIndex == 11
        then
            local classtree = subtree:add("OcaBlock.GetMostRecentParamSetIdentifier")
            -- no parameters to be decoded
            responseDissector = OcaBlockGetMostRecentParamSetIdentifier
        elseif methodIndex == 12
        then
            local classtree = subtree:add("OcaBlock.ApplyParamSet")
            OcaLibVolIdentifier(parameters(0):tvb(), fieldDefs['ocaBlockParamSet'], classtree)
            responseDissector = OcaBlockApplyParamSet
        elseif methodIndex == 13
        then
            local classtree = subtree:add("OcaBlock.GetCurrentParamSetData")
            -- no parameters to be decoded
            responseDissector = OcaBlockGetCurrentParamSetData
        elseif methodIndex == 14
        then
            local classtree = subtree:add("OcaBlock.StoreCurrentParamSetData")
            local libVolIdentifierLength = OcaLibVolIdentifier(parameters(0):tvb(), fieldDefs['ocaBlockParamSet'], classtree)
            local nameLength = OcaString(parameters(libVolIdentifierLength):tvb(), fieldDefs['ocaBlockVolumeName'], classtree)
            classtree:add(fieldDefs['ocaBlockVolumeVersion'], parameters(libVolIdentifierLength + nameLength, 4))
            responseDissector = OcaBlockStoreCurrentParamSetData
        elseif methodIndex == 15
        then
            local classtree = subtree:add("OcaBlock.GetGlobalType")
            -- no parameters to be decoded
            responseDissector = OcaBlockGetGlobalType
        elseif methodIndex == 16
        then
            local classtree = subtree:add("OcaBlock.GetONoMap")
            -- no parameters to be decoded
            responseDissector = OcaBlockGetONoMap
        elseif methodIndex == 17
        then
            local classtree = subtree:add("OcaBlock.FindObjectsByRole")
            local searchNameLength = OcaString(parameters(0):tvb(), fieldDefs['ocaBlockSearchName'], classtree)
            classtree:add(fieldDefs['ocaBlockStringComparisonType'], parameters(searchNameLength, 1))
            local searchClassIDLength = OcaClassID(parameters(searchNameLength + 1):tvb(), fieldDefs['ocaBlockSearchClassID'], classtree)
            classtree:add(fieldDefs['ocaBlockResultFlags'], parameters(searchNameLength + 1 + searchClassIDLength, 2))
            responseDissector = OcaBlockFindObjectsByRole
        elseif methodIndex == 18
        then
            local classtree = subtree:add("OcaBlock.FindObjectsByRoleRecursive")
            local searchNameLength = OcaString(parameters(0):tvb(), fieldDefs['ocaBlockSearchName'], classtree)
            classtree:add(fieldDefs['ocaBlockStringComparisonType'], parameters(searchNameLength, 1))
            local searchClassIDLength = OcaClassID(parameters(searchNameLength + 1):tvb(), fieldDefs['ocaBlockSearchClassID'], classtree)
            classtree:add(fieldDefs['ocaBlockResultFlags'], parameters(searchNameLength + 1 + searchClassIDLength, 2))
            responseDissector = OcaBlockFindObjectsByRoleRecursive
        elseif methodIndex == 19
        then
            local classtree = subtree:add("OcaBlock.FindObjectsByLabelRecursive")
            local searchNameLength = OcaString(parameters(0):tvb(), fieldDefs['ocaBlockSearchName'], classtree)
            classtree:add(fieldDefs['ocaBlockStringComparisonType'], parameters(searchNameLength, 1))
            local searchClassIDLength = OcaClassID(parameters(searchNameLength + 1):tvb(), fieldDefs['ocaBlockSearchClassID'], classtree)
            classtree:add(fieldDefs['ocaBlockResultFlags'], parameters(searchNameLength + 1 + searchClassIDLength, 2))
            responseDissector = OcaBlockFindObjectsByLabelRecursive
        elseif methodIndex == 20
        then
            local classtree = subtree:add("OcaBlock.FindObjectsByPath")
            local searchPathLength = OcaNamePath(parameters(0):tvb(), fieldDefs['ocaBlockSearchPath'], classtree)
            classtree:add(fieldDefs['ocaBlockResultFlags'], parameters(searchPathLength, 2))
            responseDissector = OcaBlockFindObjectsByPath
        else
            subtree:add("Unknown method")
        end
    end

    return responseDissector
end

fixedObjectDissector[100] = OcaBlock
