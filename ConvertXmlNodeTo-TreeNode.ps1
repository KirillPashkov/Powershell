function ConvertXmlNodeTo-TreeNode
{
    param(
        [System.Xml.XmlNode]$XmlNode,
        [System.Windows.Forms.TreeNodeCollection]$TreeNodes
    )
        $xmlNodeName = if ($xmlNode.LocalName -eq 'Name') {$xmlNode.Name} else {$xmlNode.LocalName}

        [System.Windows.Forms.TreeNode]$newTreeNode = $treeNodes.Add($xmlNodeName);
        
        switch ($xmlNode.NodeType)
        {
            'ProcessingInstruction' {
                $newTreeNode.Text = '<?' + $xmlNodeName + ' ' + $xmlNode.Value + '?>';
                break;
            }
            'XmlDeclaration' {
                $newTreeNode.Text = '<?' + $xmlNodeName + ' ' + $xmlNode.Value + '?>';
                break;
            }
            'Element' {
                $newTreeNode.Text = '<' + $xmlNodeName + '>';
                break;
            }
            'Attribute' {
                $newTreeNode.Text = 'ATTRIBUTE: ' + $xmlNodeName;
                break;
            }
            'Text' {
                $newTreeNode.Text = $xmlNode.Value;
                break;
            }
            'CDATA' {
                $newTreeNode.Text = $xmlNode.Value;
                break;
            }
            'Comment'{
                $newTreeNode.Text = "<!--" + $xmlNode.Value + "-->";
                break;
            }
        }

        if ($xmlNode.Attributes -ne $null)
        {
            foreach ($attribute in $xmlNode.Attributes)
            {
                ConvertXmlNodeTo-TreeNode $attribute $newTreeNode.Nodes;
            }
        }
        foreach ($childNode in $xmlNode.ChildNodes)
        {
            ConvertXmlNodeTo-TreeNode $childNode $newTreeNode.Nodes;
        }
}

#$TreeView.Nodes.Clear();

#ConvertXmlNodeTo-TreeNode -XmlNode $x -TreeNodes $TreeView.Nodes

#$TreeView.Nodes[0].ExpandAll()
