from .BackendSession import BackendSession

import ipywidgets as widgets
from ipywidgets import Layout, interact, interact_manual, interactive

# 
#
class InteractiveSession:

    def __init__(self, user=None, password=None):

        self.dropdown_menu = None
        self.backend = None

        if user is not None and password is not None:
            self.backend = BackendSession( user=user, password=password)
        else:
            self.login_menu = None
            self.dropdown_menu = None
            self.w_user = widgets.Text(
                value='',
                description='Username:',
                disabled=False
            )
            self.w_password = widgets.Password(
                value='',
                description='Password:',
                disabled=False
            )

            loginButton = widgets.Button(description="Login")
            loginButton.on_click(self._onLoginButtonClicked)
            
            self.login_menu = widgets.Box(children=[self.w_user,self.w_password,loginButton],
                            layout=Layout(display='flex',flex_flow='row',align_items='stretch',width='70%'))

            display(self.login_menu)

    def _onLoginButtonClicked(self,button):
        print('Logging in...')
        self.backend = BackendSession(  user=self.w_user.value,
                                        password=self.w_password.value)

    def dropdown(self):
        if(self.dropdown_menu is None):
            self._createDropdown()
        
        display(self.dropdown_menu)
    
    def _createDropdown(self):
        root = widgets.Dropdown(description = 'GROUP',
                                placeholder='Seleccione una opción...',
                                options=[('',None)] + self.backend.getChildren())
        root.observe(self._updateDropdown, 'value')
        self.dropdown_menu = widgets.VBox()
        self.dropdown_menu.children = [root]

    def _updateDropdown(self,change):
        # print()
        # for key in change:
        #   print(f'{key} ({type(change[key])}): {change[key]}')
        # print()

        # Delete all dropdowns located below the modified one
        dropdowns = list(self.dropdown_menu.children)
        dropdowns = dropdowns[:dropdowns.index(change['owner'])+1]

        # Get the children of the new selected node.
        # Note: change['new'] is the ID of the selected value
        children_list = self.backend.getChildren(change['new']) if change['new'] is not None else None

        # Only create a new dropdown if there is any children
        if children_list:   
            node = self.backend.getNode(children_list[0][1])

            new_dropdown = widgets.Dropdown(description=node['type'], options= [('',None)] + children_list,)
            new_dropdown.observe(self._updateDropdown, 'value')
            dropdowns.append(new_dropdown)
        else:
            # The assumption that if has no children is a sensor is made. This should be checked.
            sensorID = change['new']

        # Update the dropdowns
        self.dropdown_menu.children = tuple(dropdowns)








