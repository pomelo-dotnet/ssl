namespace Pomelo.Security.CaWeb.Models.ViewModels
{
    public class PostConvertPfxRequest
    {
        public string PfxPassword { get; set; }

        public string Key { get; set; }

        public string KeyPassword { get; set; } = "";
    }
}
