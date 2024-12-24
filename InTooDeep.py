import idaapi
import ida_kernwin
import ida_dirtree
import ida_funcs
import idc
from PyQt5 import QtWidgets, sip, QtCore

PLUGIN_NAME = "In Too Deep"
moveHereCustomIconId = -1
newFolderCustomIconId = -1


def getTreeForWidget(widget):
    return {
        idaapi.BWN_FUNCS: ida_dirtree.DIRTREE_FUNCS,
        
        idaapi.BWN_PSEUDOCODE: ida_dirtree.DIRTREE_FUNCS,
        
        idaapi.BWN_DISASM: ida_dirtree.DIRTREE_FUNCS,
        
        idaapi.BWN_IMPORTS: ida_dirtree.DIRTREE_IMPORTS,
        
        idaapi.BWN_LOCTYPS: ida_dirtree.DIRTREE_LOCAL_TYPES,
            
        idaapi.BWN_NAMES: ida_dirtree.DIRTREE_NAMES,
    }.get(widget, None)


def getBytesFromQStyleIcon(icon):
    pixmap = QtWidgets.QWidget().style().standardIcon(icon).pixmap(100)

    byteArray = QtCore.QByteArray()
    buff = QtCore.QBuffer(byteArray)
    buff.open(QtCore.QIODevice.WriteOnly)
    pixmap.save(buff, "PNG")

    return byteArray.data()


def getFuncUnderCursor(widget, cursorEA):
    vu = idaapi.get_widget_vdui(widget)

    if vu:
        cursorEA = vu.item.get_ea()
    else:
        opNum = idaapi.get_opnum()
        if opNum != -1:
            # Cursor under operand value with function
            opAddr = idc.get_operand_value(cursorEA, opNum)
            f = idaapi.get_func(opAddr)
            if f and f.start_ea == opAddr:
                return opAddr

    # Cursor directly over a function
    f = idaapi.get_func(cursorEA)
    if f and f.start_ea == cursorEA:
        return cursorEA


def getFuncAbsPath(ea):
    tree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    funcName = ida_funcs.get_func_name(ea)

    absPath = ""

    class treeTraversal(ida_dirtree.dirtree_visitor_t):
        def visit(self, cursor, direntry):
            if direntry.isdir or funcName != tree.get_entry_name(direntry):
                return 0

            nonlocal absPath
            absPath = tree.get_abspath(cursor)

            return -1

    tree.traverse(treeTraversal())
    return absPath


class MoveHereActionHandler(idaapi.action_handler_t):
    def __init__(self, destPath, srcPaths=None):
        ida_kernwin.action_handler_t.__init__(self)
        self.destPath = destPath
        self.srcPaths = srcPaths

    def activate(self, ctx): 
        widgetType = idaapi.get_widget_type(ctx.widget)
        treeType = getTreeForWidget(widgetType)
        tree = ida_dirtree.get_std_dirtree(treeType)
        
        if not ctx.dirtree_selection and not (widgetType == idaapi.BWN_PSEUDOCODE or widgetType == idaapi.BWN_DISASM):
            print("Please enable 'Show folders' for this view before continuing")
            return
       
        selectedItems = []
        if widgetType == idaapi.BWN_DISASM or widgetType == idaapi.BWN_PSEUDOCODE:
            ea = getFuncUnderCursor(ctx.widget, ctx.cur_ea)
            selectedItems = [getFuncAbsPath(ea)]
        elif self.srcPaths:
             selectedItems = self.srcPaths
        else:
            selectedItems = [tree.get_abspath(i) for i in ctx.dirtree_selection]

        for i in selectedItems:
            itemName = i.split("/")[-1]
            tree.rename(i, self.destPath + "/" + itemName) 

    def update(self, ctx):
        pass


class CreateNewFolderActionHandler(idaapi.action_handler_t):
    def __init__(self, destPath):
        ida_kernwin.action_handler_t.__init__(self)
        self.destPath = destPath

    def activate(self, ctx):        
        folderName = ida_kernwin.ask_str("", ida_kernwin.HIST_IDENT, "Please enter folder name")
        newFolderPath = self.destPath + "/" + folderName

        widgetType = idaapi.get_widget_type(ctx.widget)
        treeType = getTreeForWidget(widgetType)
        tree = ida_dirtree.get_std_dirtree(treeType)
        
        absPathOfSelectedItems = None
        if widgetType == idaapi.BWN_DISASM or widgetType == idaapi.BWN_PSEUDOCODE:
            # The disassembly and pseudocode views don't populate ctx.dirtree_selection, but ida_dirtree.DIRTREE_FUNCS can still be modified without the show folders view being active
            ea = getFuncUnderCursor(ctx.widget, ctx.cur_ea)
            absPathOfSelectedItems = [getFuncAbsPath(ea)]
        else:        
            if not ctx.dirtree_selection:
                print("Please enable 'Show folders' for this view before continuing")
                return
            
            absPathOfSelectedItems = [tree.get_abspath(i) for i in ctx.dirtree_selection] # Creation of a new dir will invalidate previous ctx

        tree.mkdir(newFolderPath)

        mh = MoveHereActionHandler(newFolderPath, srcPaths=absPathOfSelectedItems)
        mh.activate(ctx)

    def update(self, ctx):
        pass


class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        widgetType = idaapi.get_widget_type(widget)
        treeType = getTreeForWidget(widgetType)
        if not treeType:
            return  # Don't show menu for views that don't support folders
        
        tree = ida_dirtree.get_std_dirtree(treeType)

        if widgetType == idaapi.BWN_DISASM or widgetType == idaapi.BWN_PSEUDOCODE:
            if getFuncUnderCursor(widget, idaapi.get_screen_ea()) == None:
                return  # Don't show menu in the disassembly or pseudocode view if cursor is not over a function

        class treeTraversal(ida_dirtree.dirtree_visitor_t):
            def visit(self, cursor, direntry):
                global moveHereCustomIconId, newFolderCustomIconId

                if not direntry.isdir:
                    return 0

                absPath = tree.get_abspath(cursor)

                mhHandler = MoveHereActionHandler(absPath)
                cnfHandler = CreateNewFolderActionHandler(absPath)

                if absPath == "/":
                    absPath = "/[root]"

                path = "Move To" + absPath + "/"

                idaapi.attach_dynamic_action_to_popup(
                    widget,
                    popup,
                    idaapi.action_desc_t(
                        None, 
                        "Here", 
                        mhHandler, 
                        None,
                        None, 
                        moveHereCustomIconId
                    ),
                    path,
                    idaapi.SETMENU_APP,
                )

                idaapi.attach_dynamic_action_to_popup(
                    widget,
                    popup,
                    idaapi.action_desc_t(
                        None,
                        "Create New Folder",
                        cnfHandler,
                        None,
                        None,
                        newFolderCustomIconId,
                    ),
                    path,
                    idaapi.SETMENU_APP,
                )

                return 0

        tree.traverse(treeTraversal())


class PluginIconHook(idaapi.UI_Hooks):
    def updated_actions(self):
        global PLUGIN_NAME, moveHereCustomIconId
        ida_kernwin.update_action_icon("Edit/Plugins/" + PLUGIN_NAME, moveHereCustomIconId)


class InTooDeepPlugin(idaapi.plugin_t):
    comment = "Make it easier to manage folders in IDA"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""
    flags = 0

    def init(self):
        global PLUGIN_NAME, moveHereCustomIconId, newFolderCustomIconId

        moveHereCustomIconId = idaapi.load_custom_icon(
            data=getBytesFromQStyleIcon(QtWidgets.QStyle.SP_DirClosedIcon), format="png"
        )
        newFolderCustomIconId = idaapi.load_custom_icon(
            data=getBytesFromQStyleIcon(QtWidgets.QStyle.SP_DirOpenIcon), format="png"
        )

        self.contextMenuHook = ContextMenuHooks()
        self.contextMenuHook.hook()
        
        self.pluginIconHook = PluginIconHook()
        self.pluginIconHook.hook()

        print("{} - Hooks registered".format(PLUGIN_NAME))
        return idaapi.PLUGIN_KEEP

    def run(*args):
        pass

    def term(self):
        global moveHereCustomIconId, newFolderCustomIconId

        idaapi.free_custom_icon(moveHereCustomIconId)
        idaapi.free_custom_icon(newFolderCustomIconId)

        self.contextMenuHook.unhook()
        self.pluginIconHook.unhook()


def PLUGIN_ENTRY():
    return InTooDeepPlugin()
