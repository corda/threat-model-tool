<%page args="assets"/>

<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
  <tr>
    <th>Title (ID)</th><th>Description</th><th>Properties</th>
  </tr>

  % for asset in assets:
  <tr>
    <td><strong><a href="#${asset.id}">${asset.title}</a></strong></td>
    <td><b>
    <%
    type = asset.type
    if hasattr(asset, 'properties') and 'type' in asset.properties:
      type = asset.properties['type']
    %>
    ${type}
    </b><br>${asset.description}</td>
    <td>${asset.propertiesHTML()}</td>
  </tr>
  % endfor ##asset
</table>
