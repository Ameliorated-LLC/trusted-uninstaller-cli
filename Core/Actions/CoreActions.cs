using System.Threading.Tasks;

namespace Core.Actions
{
    public interface ICoreAction
    {
        public void RunTask(bool logExceptions);
    }
    public static class CoreActions
    {
        public static void SafeRun(ICoreAction action, bool logExceptions = false)
        {
            Wrap.ExecuteSafe(() => action.RunTask(logExceptions), logExceptions);
        }
    }
}
